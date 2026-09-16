import "pe"
rule _Trojan_Sysbot_Trojan_VB_OJW_5_Trojan_Sysbot_Trojan_VB_OJW_8_Vir_213 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Trojan.VB.OJW_5.vir, Trojan.Sysbot_Trojan.VB.OJW_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3600b4cf119a93fa453285f612d7afc13177d3540822abd6bf06ab2836884336"
    hash2       = "60a3853377ca4c671710d2b267b1572791fa71f0b4f2975ed07cc8916975058d"
    hash3       = "e6b10f28c4b62c13b775cc753aabecaed274524e9431ca4a2a379832e6054707"

  strings:
    $s1 = "PROVIDER=Microsoft.Jet.OLEDB.3.51;Data Source=C:\\Program Files\\Microsoft Visual Studio\\VB98\\NWIND.MDB;f" fullword wide
    $s2 = "PROVIDER=Microsoft.Jet.OLEDB.3.51;Data Source=C:\\Program Files\\Microsoft Visual Studio\\VB98\\NWIND.MDB;" fullword wide
    $s3 = "Place code here to set options w/o closing dialog!" fullword wide
    $s4 = "Place code here to set options and close dialog!" fullword wide
    $s5 = "Data error event hit err:" fullword wide
    $s6 = "select Flags,Form,Module,Name,ReplicationVersion,Type,TypeInfo,Version from MSysModules2" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "135e92fc9902f3140f2e5a51458efdf0" and (all of them)
    ) or (all of them)
}