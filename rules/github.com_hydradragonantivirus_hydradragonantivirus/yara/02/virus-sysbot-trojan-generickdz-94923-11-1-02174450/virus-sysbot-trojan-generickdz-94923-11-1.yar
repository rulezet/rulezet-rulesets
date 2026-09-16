rule Virus_Sysbot_Trojan_GenericKDZ_94923_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef6b028e3c938caf7636a05cc9d9077629d261c9ad68e9e5ed29300ec719b818"

  strings:
    $s1 = "pm636n5G0eLQfbLASJ.reiyxi1y7E41x3QCna/XDVbcCnymMMZtQdMR9/BNV25vAfh5YVlmJ7vD`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s2 = "<Module>{69539997-F210-4F6A-8F5E-56DBBF94816E}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}