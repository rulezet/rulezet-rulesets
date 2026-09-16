rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_344 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash4       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash5       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1  = "k(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";" ascii
    $s2  = "n \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s3  = "){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";}" ascii
    $s4  = "urn \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s5  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s6  = "),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){r" ascii
    $s7  = "on fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s8  = "b\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s9  = "Ts\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s10 = "ck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py" ascii
    $s11 = "TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(functio" ascii
    $s12 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s13 = "})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuc" ascii
    $s14 = "{return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})" ascii
    $s15 = "k(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\"" ascii
    $s16 = "n \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s17 = "urn \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s18 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s19 = "urn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s20 = "ck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Na\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}