rule sig_20160106_c77fda58d7fb7f8589722cf3a06a9d52 {
  meta:
    description = "datamaliciousorder - file 20160106_c77fda58d7fb7f8589722cf3a06a9d52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9094c76bd8cd2ac4a47ffb376b9204f611876631ff3dba639eb38a67d1334ff"

  strings:
    $s1 = "var zmp='fjbuunncxcazthkigioxjnge kfdeolur(ucfofrgx,pp jpfkenhe,zu tiruvnzc)td{sc kz ckvqgayqrzi kwwkasgr iq=rf tbnjaeerwpf mfAa" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}