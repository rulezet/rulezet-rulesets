import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_279_2_Vir_229 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_279_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d6ed63e357100a38b5bb4f4a256be07e34960bf25dbf0cc7d8f6b66e06d2df3"
    hash2       = "e6313b89f0b3cd87fdbc525f40a4d1dcf792afb564b8d97722b7df17eb805f69"
    hash3       = "2ccebd1dd2000856f9aa8ef98853f7ead9a30857e615e094aa2079cdddd1252e"

  strings:
    $s1 = "Port Open failed: " fullword wide
    $s2 = "Write Log" fullword wide
    $s3 = "$STATIC$portsRefresh_Tick$2001$portnameCount" fullword ascii
    $s4 = "Port was disconnected" fullword wide
    $s5 = "Bwl IR Terminal" fullword wide
    $s6 = " q#IdLY" fullword ascii
    $s7 = "Add Time" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}