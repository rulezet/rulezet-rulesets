rule Trojan_Danger_Trojan_Agent_EICV_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.EICV_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1985af13b733ba6aca1f7e949f583df73d57cf49a924cb33a2912ce004ab59ef"

  strings:
    $s1 = "uOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}