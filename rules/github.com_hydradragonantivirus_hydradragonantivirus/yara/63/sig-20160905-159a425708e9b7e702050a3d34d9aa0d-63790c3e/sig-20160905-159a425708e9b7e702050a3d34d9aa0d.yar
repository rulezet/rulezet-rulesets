rule sig_20160905_159a425708e9b7e702050a3d34d9aa0d {
  meta:
    description = "datamaliciousorder - file 20160905_159a425708e9b7e702050a3d34d9aa0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d58fbbc9403248adf39ffff12d3e4fa674c74baad170e2974515326e7a1542c"

  strings:
    $x1 = "objShell.ShellExecute(\"PowerShell.exe\", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New-" ascii
    $x2 = "objShell.ShellExecute(\"PowerShell.exe\", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New-" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}