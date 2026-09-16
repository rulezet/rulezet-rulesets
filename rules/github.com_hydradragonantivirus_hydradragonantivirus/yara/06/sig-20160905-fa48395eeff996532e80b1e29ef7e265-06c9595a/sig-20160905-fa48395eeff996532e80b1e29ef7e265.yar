rule sig_20160905_fa48395eeff996532e80b1e29ef7e265 {
  meta:
    description = "datamaliciousorder - file 20160905_fa48395eeff996532e80b1e29ef7e265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "579955f31eb99a660c1f66026157c764f75dd953820852c64ef7976ad34324da"

  strings:
    $x1 = "objShell.ShellExecute(\"PowerShell.exe\", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New-" ascii
    $x2 = "objShell.ShellExecute(\"PowerShell.exe\", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New-" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}