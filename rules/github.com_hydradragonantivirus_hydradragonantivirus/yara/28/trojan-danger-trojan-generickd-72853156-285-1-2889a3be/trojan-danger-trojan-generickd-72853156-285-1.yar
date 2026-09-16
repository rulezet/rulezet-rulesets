rule Trojan_Danger_Trojan_GenericKD_72853156_285_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_285_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1b2fdf8fc5ccfacc2ddefa98f8cd9b04f083cc459f64c1f2dcc3e92b28d7ca1"

  strings:
    $s1  = "SysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqNon Employee User - External: is defined as an individual, who is" ascii
    $s2  = "turn on the Office Roaming Service. Turning on the Office Roaming Service sends certain settingsSysqamqqvaqqdSysqemrwttnSysqamqq" ascii
    $s3  = "sqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqd" ascii
    $s4  = "Microsoft Ireland Operations Limited makes the limited warranty. To make a claim under the limited qdSysqamqqvaqqdSysqamqqvaqqdS" ascii
    $s5  = "Microsoft Ireland Operations Limited makes the limited warranty. To make a claim under the limited qdSysqamqqvaqqdSysqamqqvaqqdS" ascii
    $s6  = "turn on the Office Roaming Service. Turning on the Office Roaming Service sends certain settingsSysqamqqvaqqdSysqemrwttnSysqamqq" ascii
    $s7  = " to desupport its programs or particular versions of its programs. You will be notified in advance" fullword ascii
    $s8  = "dSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqOracle reserves the right" ascii
    $s9  = " not your employee, contractor or outsourcer, authorized" fullword ascii
    $s10 = "dSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqprograms and/or any services, you will follow Oracl" ascii
    $s11 = "sqamqqvaqProfessional User 2003 " fullword ascii
    $s12 = "dSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqprograms and/or any services, you will follow Oracl" ascii
    $s13 = "amqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSy" ascii
    $s14 = "ection does not excuse either party" fullword ascii
    $s15 = "other Person.sqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSySysqemjvfnm" ascii
    $s16 = "other Person.sqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSySysqemjvfnm" ascii
    $s17 = "dSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqOracle reserves the right" ascii
    $s18 = "Microsoft Software License Terms link or going toysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSy" ascii
    $s19 = "own most important confidential information or a reasonable degree of care, whichever is greater; (b) to maintain agreementsqqdS" ascii
    $s20 = "Export laws and regulations of the United States and any other relevant local export laws and regulations apply to theysqamqqvaq" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}