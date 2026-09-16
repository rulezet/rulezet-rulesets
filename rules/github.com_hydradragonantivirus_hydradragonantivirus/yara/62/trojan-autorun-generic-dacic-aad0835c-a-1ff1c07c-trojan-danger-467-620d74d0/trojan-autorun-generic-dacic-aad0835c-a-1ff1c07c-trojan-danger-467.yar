import "pe"
rule _Trojan_Autorun_Generic_Dacic_AAD0835C_A_1FF1C07C_Trojan_Danger__467 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Generic.Dacic.AAD0835C.A.1FF1C07C.vir, Trojan.Danger_Trojan.GenericKD.72853156_205_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_225_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6b9d4fb232578611a9ad8349cf9ce8a6287b6aecba62a4cde858b61f9529c57"
    hash2       = "300f363666f6247998e69dfd1068f93c1ad5bcd6ba38459f3829df380e6c4b59"
    hash3       = "506843faeef2a2b09cef9cd389ed64296d01cbfa575a45960a6f9ff759b57004"

  strings:
    $s1  = "online to Microsoft servers, where they are stored and downloaded to your computer the next time youqvaqqdSysqamqqvaqqdSysqamqqv" ascii
    $s2  = "qqvaqqdSysqamyou are granted unlimited access to initiate work requests, view work request status and view scheduled completion " ascii
    $s3  = "IRE_OLSA_V120103_Def_V122304 Page 5 of 11 aqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysq" ascii
    $s4  = "qamqqvaqqdSysqamqqvaqqdSysqamqqvaqEmployee Users, but must be licensed as Professional Users. Additionally, your technical suppo" ascii
    $s5  = "online to Microsoft servers, where they are stored and downloaded to your computer the next time youqvaqqdSysqamqqvaqqdSysqamqqv" ascii
    $s6  = "qamqqvaqqdSysqamqqvaqqdSysqamqqvaqEmployee Users, but must be licensed as Professional Users. Additionally, your technical suppo" ascii
    $s7  = "rt personnel that require" fullword ascii
    $s8  = "end of this agreement.qqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqaSysqemjvfnmSysqemkeexiSysqemmsnywSysqamqqv" ascii
    $s9  = "end of this agreement.qqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqaSysqemjvfnmSysqemkeexiSysqemmsnywSysqamqqv" ascii
    $s10 = "IRE_OLSA_V120103_Def_V122304 Page 5 of 11 aqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysq" ascii
    $s11 = "ose not to use them." fullword ascii
    $s12 = "aqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvathese features can be switched off or you can cho" ascii
    $s13 = "Electronic Order Line: is defined as the total number of distinct order lines entered electronically into the Oracle OrderSysqam" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f81af0e74386e5451cfb9fa32f1293e4" and (8 of them)
    ) or (all of them)
}