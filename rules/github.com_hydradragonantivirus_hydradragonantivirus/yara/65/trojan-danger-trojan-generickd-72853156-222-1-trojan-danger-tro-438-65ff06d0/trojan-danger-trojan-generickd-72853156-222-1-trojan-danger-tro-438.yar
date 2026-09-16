import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_222_1_Trojan_Danger_Tro_438 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_222_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_238_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_292_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28321d78da68017c7cb67e6205fba1cca7b6f16609b53b3ba625e158e68222c3"
    hash2       = "1fef4afe2e8f2416481f4d95aeced373fa15adfbd80f1dfe1745a41624efda46"
    hash3       = "7cc8bcc6679245fa2b63b419f7a11736ff9e1284343a25b18231c741a86496dc"

  strings:
    $s1  = "are responsible for ensuring that the named user plus per processor minimums are maintained for the programs contained in thevaq" ascii
    $s2  = "are responsible for ensuring that the named user plus per processor minimums are maintained for the programs contained in thevaq" ascii
    $s3  = "t warrant that the Oracle University Online service will be provided uninterrupted or error-free." fullword ascii
    $s4  = "vaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqaOracle does no" ascii
    $s5  = "TRMs to those of your employees and agents who have a \"need to know\" consistent with the purposes for which such TRMsaqqdSysqa" ascii
    $s6  = "TRMs to those of your employees and agents who have a \"need to know\" consistent with the purposes for which such TRMsaqqdSysqa" ascii
    $s7  = "qvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqa" ascii
    $s8  = "dSysqamqqvaqqdSysqamqqvaqqdSU.S. $1,000 (Seven hundred and seventy-two euros) increment of your gross annual revenue as reported" ascii
    $s9  = "ATTORNEY GENERA L ACTION, OR IN A NY OTHER PROCEEDING IN WHICH EITHER PARTYqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqq" ascii
    $s10 = "mqqvaArbitration Association (the " fullword ascii
    $s11 = "ATTORNEY GENERA L ACTION, OR IN A NY OTHER PROCEEDING IN WHICH EITHER PARTYqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqq" ascii
    $s12 = "vaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqaOracle does no" ascii
    $s13 = "where you installed the software. Microsoft uses this information to make the Internet-based featuresSysqamqqvaqqdSysqamqqvaqqdS" ascii
    $s14 = "where you installed the software. Microsoft uses this information to make the Internet-based featuresSysqamqqvaqqdSysqamqqvaqqdS" ascii
    $s15 = "may renew your order for an additional one year term at the then current Online Library rate by contacting your local Oraclemqqv" ascii
    $s16 = "may renew your order for an additional one year term at the then current Online Library rate by contacting your local Oraclemqqv" ascii
    $s17 = " to the SEC in your" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "9e3d49b744c0b3b278a2c35676f6abed" and (8 of them)
    ) or (all of them)
}