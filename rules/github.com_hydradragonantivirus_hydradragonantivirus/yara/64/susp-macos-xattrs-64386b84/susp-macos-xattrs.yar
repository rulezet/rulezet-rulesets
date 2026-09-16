rule susp_macos_xattrs {
  meta:
    description = "Identify macOS executables that manipulate extended attributes (xattr's)"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.13"
    DaysofYARA  = "72/100"

  strings:
    $xattr_quarantine = "com.apple.quarantine"
    $xattr_macl       = "com.apple.macl"
    $xattr_provenance = "com.apple.provenance"
    $xattr_sip        = "com.apple.rootless"

    $allow_shipitsqrl = "SQRLShipIt"
    $allow_kbfs       = "kbfs/libfuse.(*QuarantineXattrHandler)"
    $allow_goupdater  = "go-updater/keybase.context.Apply"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    uint32(0xc) == 0x2 and      any of ($xattr*) and
    not any of ($allow*)
}