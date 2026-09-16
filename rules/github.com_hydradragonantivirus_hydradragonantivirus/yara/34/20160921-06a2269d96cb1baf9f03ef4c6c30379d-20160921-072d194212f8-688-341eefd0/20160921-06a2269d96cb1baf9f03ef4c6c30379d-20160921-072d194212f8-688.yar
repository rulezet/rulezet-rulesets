rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_072d194212f8_688 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash3       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash4       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash5       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash6       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash7       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash8       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash9       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash10      = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash11      = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash12      = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"
    hash13      = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"
    hash14      = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1  = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){r" ascii
    $s2  = "n fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"W" ascii
    $s3  = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Za\";})(),(f" ascii
    $s4  = "uck(){return \"Ve\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu" ascii
    $s5  = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s6  = "n \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s7  = ",(function fuck(){return \"Fv\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){re" ascii
    $s8  = "nction fuck(){return \"PDf\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){retur" ascii
    $s9  = "){return \"Qh\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";}" ascii
    $s10 = "(){return \"We\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})" ascii
    $s11 = "(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})" ascii
    $s12 = "unction fuck(){return \"EHo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retu" ascii
    $s13 = "ck(){return \"We\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";" ascii
    $s14 = "unction fuck(){return \"XHj\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){ret" ascii
    $s15 = "u\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZWu\";})(),(function " ascii
    $s16 = "return \"Fv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s17 = "tion fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return" ascii
    $s18 = "rn \"XHj\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s19 = "ck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Wo\"" ascii
    $s20 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}