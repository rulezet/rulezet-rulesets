import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_avZ_amBwvTb_2_2_Virus_Hijac_6 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.avZ@amBwvTb_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.avZ@amBwvTb_3_2.vir, VirusShareTrojanSiggen1961528.vir, VirusShareTrojanSiggen1961528_1.vir, VirusShareTrojanSiggen1961528_10.vir, VirusShareTrojanSiggen1961528_11.vir, VirusShareTrojanSiggen1961528_12.vir, VirusShareTrojanSiggen1961528_14.vir, VirusShareTrojanSiggen1961528_15.vir, VirusShareTrojanSiggen1961528_2.vir, VirusShareTrojanSiggen1961528_3.vir, VirusShareTrojanSiggen1961528_4.vir, VirusShareTrojanSiggen1961528_5.vir, VirusShareTrojanSiggen1961528_6.vir, VirusShareTrojanSiggen1961528_8.vir, VirusShareTrojanSiggen1961528_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7df6f5ffa313c0e9092abb5c9187a8d19c4ae9bf0906cb1a73d90f5877bd0c52"
    hash2       = "0337de28411eeb2ed992a2c364ae34bca947f2e57ffcf9c37148e6e633179dce"
    hash3       = "5e802146d4cd6e6769e8da093f8d3d33e01439147f43905f25ed3f0cbcaae91a"
    hash4       = "cee935b6be25b773152ffe9fa94636bdf50402778990564c2dfb3e8926de9df0"
    hash5       = "78fa12bed5e8190cbf8166dc66407e0203679e68633b7caf8f0ff46c78757616"
    hash6       = "464cac325d36158c4127500be27781d59e11defbf02dfea71ad44372fed7bc0b"
    hash7       = "9f164e56ff1014128ffefa25c7ae0bd7703d9b037df12cfbcb51ea7f64c0dbcd"
    hash8       = "603b13e65694e21fa1d73e0a2af9b33cdd679e4b89d44314b0e0f8eae58cce9b"
    hash9       = "74d3a77bd59a8d468447c16bd16cfe5deb8384f8301fe0e51050c824ec5c378f"
    hash10      = "f374c603980975a3be97f8308ef4a199c1062fb38001ae3b2cb0f52bbb621935"
    hash11      = "60f56b7b143d4b8e7769aa254618da0fc7f64eb2e3685502b607d47020508464"
    hash12      = "e1d6491243de6803fd4ad5791cd60fd9f054fd2d186bc8aeaaaead8941e81fa7"
    hash13      = "fdbef9022773610fe53a42eb98c7ebe842f71323731a909af330fac77e7edbe4"
    hash14      = "94d1747e5b6abce14df29d2b9282e04d3efad4c079fe677e9dd3f9f439c0c581"
    hash15      = "ed4e6766816bcadf5374cea1606d5b12ad6777c584c893da30dff67cb6ea816d"
    hash16      = "a78ac07f07e3d4213f39e9f3f1b6aadc3e9891cfd344dc1882617bc5f527c021"

  strings:
    $s1 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath  \"" fullword ascii
    $s2 = "(target" fullword ascii
    $s3 = "(current" fullword ascii
    $s4 = ",initial" fullword ascii
    $s5 = "\"CONTEXT" fullword ascii
    $s6 = "\\(mask" fullword ascii
    $s7 = "[shift" fullword ascii
    $s8 = "#trace" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f9fc0ecba4bcf3f4eadacd9b358488bc" and (all of them)
    ) or (all of them)
}