import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_232_2_Tro_120 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_232_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_233_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_234_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_235_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc8324152892b2fc30fd2574d990150aeecbe7b3e5b871d884c6644a16ede4ed"
    hash2       = "abf5690018f60f621f9bd9e5e342d310825e3b3ad2d8ddfb0c5b1b0de95ee846"
    hash3       = "64c3c3a5004d786f14ced03e295463bebaa1ab08c59b8287001c15aac69e3521"
    hash4       = "f285919ddd1e956b6bcb0572ab1eeca5553617ee8e84f5afe564f63e3d8477cb"

  strings:
    $s1  = " thousand " fullword wide
    $s2  = " hundred and " fullword wide
    $s3  = "<prime>5__3" fullword ascii
    $s4  = "<route>5__5" fullword ascii
    $s5  = "<Sequence>d__13" fullword ascii
    $s6  = "<Range>d__4" fullword ascii
    $s7  = "<number>5__1" fullword ascii
    $s8  = "<direction>5__1" fullword ascii
    $s9  = "<Range>d__2" fullword ascii
    $s10 = "Couldn't parse input!" fullword wide
    $s11 = "Please, enter sides: A B C" fullword wide
    $s12 = "  Found " fullword wide
    $s13 = "Invalid Triangle: sum of two sides cannot be less than the third side!" fullword wide
    $s14 = "Is Scalene? :" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}