rule sig_20160908_f692000612b59b6dc5e4e5510dfae151 {
  meta:
    description = "datamaliciousorder - file 20160908_f692000612b59b6dc5e4e5510dfae151.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cd19f49fdfb60aa1586691557317df650ff1a75bc2d5be512a2c7890b510b95"

  strings:
    $x1 = "kaktotak.ShellExecute(\"PowerShell.exe \", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New" ascii
    $x2 = "kaktotak.ShellExecute(\"PowerShell.exe \", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New" ascii
    $s3 = "Process 'tak.exe'\", \"\", \"open\", 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}