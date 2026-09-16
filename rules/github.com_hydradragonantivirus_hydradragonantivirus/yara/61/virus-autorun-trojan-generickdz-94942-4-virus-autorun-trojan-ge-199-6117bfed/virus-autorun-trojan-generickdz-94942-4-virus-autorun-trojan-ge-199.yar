rule _Virus_Autorun_Trojan_GenericKDZ_94942_4_Virus_Autorun_Trojan_Ge_199 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Trojan.GenericKDZ.94942_4.vir, Virus.Autorun_Trojan.GenericKDZ.94942_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42856ebb178057d425b0915032faa9243a470593208790861c68cd3115a13240"
    hash2       = "f424124429184fcce5f03de260e2a123484d1943b89552c527f43cf7d593794c"
    hash3       = "481661ee588977620bbae38616277f88fbe6796ccad47d65205a8d061ef43bb1"
    hash4       = "bc0068b0dd00d800c6a777227a1aecddb53b886ed33ee9b6b5694b0edbcb4c31"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><asmv1:assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xml" ascii
    $s2 = "shimgenerator is a product of RealDimensions Software, LLC - All Rights Reserved. Use of shimgenerator must comply with its prop" wide
    $s3 = "shimgenerator is a product of RealDimensions Software, LLC - All Rights Reserved. Use of shimgenerator must comply with its prop" ascii
    $s4 = " 2013 - 2017, RealDimensions Software, LLC - All Rights Reserved." fullword wide
    $s5 = ".NET Framework 4R" fullword ascii
    $s6 = "[assembly: AssemblyTitle(@\"{{AssemblyTitle}} - shim\")]" fullword ascii
    $s7 = "ietary license." fullword ascii
    $s8 = "[assembly: AssemblyProduct(@\"{{AssemblyProduct}}\")]" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and all of them)
    ) or (all of them)
}