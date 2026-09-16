rule sig_20160811_1ee3c41b1d6ed2da76f1f88b62e10ae1 {
  meta:
    description = "datamaliciousorder - file 20160811_1ee3c41b1d6ed2da76f1f88b62e10ae1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2af4ed7af0804373432686d4e5199e886cb0fb54a8448d9b55ac1c171572e9c7"

  strings:
    $x1 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -window^style hi^dden (New-Object Sys" ascii
    $x2 = "lidizzz.ShellExecute(\"cmd.exe\", \"/c pow^ershell.exe -ExecutionPolicy bypass -nopro^file -window^style hi^dden (New-Object Sys" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}