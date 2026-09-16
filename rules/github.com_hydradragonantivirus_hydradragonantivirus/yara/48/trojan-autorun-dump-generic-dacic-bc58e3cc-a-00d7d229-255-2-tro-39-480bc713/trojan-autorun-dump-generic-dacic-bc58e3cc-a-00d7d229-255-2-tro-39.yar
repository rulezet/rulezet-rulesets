import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_255_2_Tro_39 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_255_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_256_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@a4YD!Xe_13_1.vir, Virus.Injector_Generic.Viking.46B92555_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42234069fbe4322917ddba734dc7455263716771762adf1377dc1e5369726592"
    hash2       = "76b16dadecbae9be2741ea7ff27c195601ef201b49ffe2a79241b7bd442447da"
    hash3       = "c11572eed6084afa9d7744f6abaf9c6f41c9826a5656d3ab5835c5b4d6c86e9f"
    hash4       = "12c620e143987ad28fe072cdd8dfc5b0e2cde3492cae25168e13435463323d18"

  strings:
    $s1  = " If No Password, Click here -->>>" fullword ascii
    $s2  = "Add System Users" fullword ascii
    $s3  = "Login Here" fullword ascii
    $s4  = "2Kapenguria District Hospital - Doctors Appointment" fullword ascii
    $s5  = "/Kapenguria District Hospital - Doctors Register" fullword ascii
    $s6  = "+Kapenguria District Hospital - Ward Details" fullword ascii
    $s7  = "2Kapenguria District Hospital - Diagnosis Interface" fullword ascii
    $s8  = "$Kapenguria District Hospital - Staff" fullword ascii
    $s9  = "-Kapenguria District Hospital - Ward Admission" fullword ascii
    $s10 = "1Kapenguria District Hospital - Patients Interface" fullword ascii
    $s11 = ".Kapenguria District Hospital - Billing Details" fullword ascii
    $s12 = "-Kapenguria District Hospital - Nurse Register" fullword ascii
    $s13 = "+Specify Configuration Details to the Server" fullword ascii
    $s14 = "8Database Server Configuration window-Patients Record MIS" fullword ascii
    $s15 = "Doctor's Comments" fullword ascii
    $s16 = "Print Diagnosis Report" fullword ascii
    $s17 = "Appointment Report" fullword ascii
    $s18 = "Display Report" fullword ascii
    $s19 = "-Patients Record Management Information System" fullword ascii
    $s20 = "Admitted" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}