rule Trojan_Danger_Trojan_GenericKD_67166905_375_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_375_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb65bafe8b44c708ce33097832b5c9a675e59e2183beed9d6ccc0803e47b611e"

  strings:
    $s1 = "^+Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}