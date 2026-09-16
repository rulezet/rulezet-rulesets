rule _Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_77_1_T_282 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_77_1.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_78_1.vir, Virus.Hijack_Trojan.Generic.267644.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8089711a14b61f7674e84027fc32fa7638c8507184f79b1ef25a98ac1561a102"
    hash2       = "79b6fc6e493e77b6bbd6067ec041ac26af8e3a4b7bbf519b503cb0da40779c51"
    hash3       = "6c123d44387cde795292fdd2d976edfd64eddd8793931262e68da88e929b0f23"

  strings:
    $s1 = "INJECT" fullword ascii
    $s2 = "Onboard HSP56 Modem Adapter Configuration And Management. If the service is stopped, the internal modem will not be able to work" ascii
    $s3 = "Onboard HSP56 Modem Adapter Configuration And Management. If the service is stopped, the internal modem will not be able to work" ascii
    $s4 = " properly. If this service is disabled, any services that explicitly depend on it will fail to start." fullword ascii
    $s5 = "Internal Modem Support" fullword ascii
    $s6 = "NetWork Monitor Control" fullword wide
    $s7 = "Copyright (C) Microsoft Corp. 1991-2001" fullword wide
    $s8 = "BaNnEr" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}