import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_104013_3_Trojan_Autorun_Trojan_560 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.104013_3.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_24.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_25.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_29.vir, Virus.Hijack_Backdoor.Hangup.B_40_1.vir, Virus.Hijack_Backdoor.Hangup.B_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f33d2da0edb8120ac80a60c1c83608907b95c0c7a37e35f2e5c99ee55020c31"
    hash2       = "a872a6f3226de24429987a3e6351ee276b0e30a2ad2193879e6fec7fe6319f8e"
    hash3       = "bdfe90b11c572a0ef860589682d16a14d576cb5367041a08d658c589e6411a7a"
    hash4       = "6bdf080f27fb110bababc7923d9b6e4aafa7cd95946ca26d5bf57a31cdcc1ec0"
    hash5       = "0028b1d14b0fc39e121297d797cbabf5429fad33ba32f09220ef6fdbfac64239"
    hash6       = "9e4b18969cc6d3391c29c040b84ca2e655a7900d87cdb2d19a1c4e981846b8a6"

  strings:
    $s1 = "ntiality of the TRMs as you exercise to safeguard the confidentiality of your" fullword ascii
    $s2 = "he TRMs as you exercise to safeguard the confidentiality of your" fullword ascii
    $s3 = "available to you, in accordance with the Office 2013 Privacy Stapayments over time of some or all of the sums due under your ord" ascii
    $s4 = "available to you, in accordance with the Office 2013 Privacy Stapayments over time of some or all of the sums due under your ord" ascii
    $s5 = "available to you, in accordance with the Office 2013 Privacy Sta" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b124a9ac34be63e65932f42f748abcd1" and (all of them)
    ) or (all of them)
}