import "pe"
rule _Trojan_Autorun_Generic_Dacic_E1F05845_A_489D47DA_Trojan_Autorun_256 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Generic.Dacic.E1F05845.A.489D47DA.vir, Trojan.Autorun_Generic.Dacic.E1F05845.A.489D47DA_1.vir, Trojan.Autorun_Trojan.GenericKDZ.74315.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3a740f92d926d52b649bfc452637b1495bbd25b5e8e887318db1e3111b4b10d"
    hash2       = "d435243e0254f90079db2bfdb75c15b3d56adb65f9bdc6a4e45486e8e193148b"
    hash3       = "8bc1e5b673a3530f7d6a960763cdb82bcf5d937c5576f399d92b7ed4ec437334"

  strings:
    $s1 = "QQPassHook Library" fullword ascii
    $s2 = "Height<NA" fullword ascii
    $s3 = "Color(OA" fullword ascii
    $s4 = "Action@HB" fullword ascii
    $s5 = "Default IME7002" fullword ascii
    $s6 = "Microsoft File exHook library" fullword wide
    $s7 = "Caption$MA" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d5ada287cb0bdf614b7546b62f89ebb1" and (all of them)
    ) or (all of them)
}