rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_453 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash4       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash5       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash6       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"
    hash7       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1  = "{return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s2  = "tion fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s3  = "k(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";" ascii
    $s4  = "ion fuck(){return \"Xw\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return " ascii
    $s5  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){re" ascii
    $s6  = "eturn \"Pc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xg\";})(),(f" ascii
    $s7  = "rn \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s8  = ")(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s9  = "on fuck(){return \"XHj\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"" ascii
    $s10 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MIl\";})(),(" ascii
    $s11 = ";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Av\";})(),(function fu" ascii
    $s12 = ",(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){r" ascii
    $s13 = "k(){return \"UXf\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Fv\";}" ascii
    $s14 = "Wn\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function" ascii
    $s15 = "YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(functio" ascii
    $s16 = "ction fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s17 = "nction fuck(){return \"Yk\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){retur" ascii
    $s18 = "\"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii
    $s19 = "n fuck(){return \"Sx\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw" ascii
    $s20 = "{return \"LGo\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Za\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}