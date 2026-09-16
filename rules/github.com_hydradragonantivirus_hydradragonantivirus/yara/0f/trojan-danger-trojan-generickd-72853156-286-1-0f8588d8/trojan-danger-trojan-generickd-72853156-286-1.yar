rule Trojan_Danger_Trojan_GenericKD_72853156_286_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_286_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "204ef7168188632df0ca16e8b360970081a23ca0c73c8b31d80ce56cc0542188"

  strings:
    $s1 = "genuine Microsoft software. To identify genuine Microsoft software, see howtotell.com.SysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSys" ascii
    $s2 = "genuine Microsoft software. To identify genuine Microsoft software, see howtotell.com.SysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSys" ascii
    $s3 = "with your employees and agents that protect the confidentiality and proprietary rights of the confidential information of thirdq" ascii
    $s4 = "with your employees and agents that protect the confidentiality and proprietary rights of the confidential information of thirdq" ascii
    $s5 = "Alias attribute is invalid in the profile schema." fullword wide
    $s6 = "Alias attribute value is not unique in the profile." fullword wide
    $s7 = "udents is a fraction, that number will be rounded to the nearest" fullword ascii
    $s8 = "SysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqyour policies for student classification. If the number of FTE St" ascii
    $s9 = "SysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqyour policies for student classification. If the number of FTE St" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}