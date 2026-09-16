rule _20160921_4c2bf112991da80cf65c9f462d7503be_20160921_515ffdda2060_5125 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c2bf112991da80cf65c9f462d7503be.js, 20160921_515ffdda2060abfddd0b1faaa82a6279.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_9c64236400e63181393ce4bc58f634a5.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_cff8867bbb427ac014f0546c00ad8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2e5ee0ebdd9746b0055379071a47434cdd28be3788ad04e886f8bd01e0746c1"
    hash2       = "e66d45deceae626136192ed805b6d7d4dc1cb2be6956a53702353ef221f89c18"
    hash3       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash4       = "2b1d27f440a3f4232e02265ce38f6eee5a715bff67e056aca1a1c800909c0e37"
    hash5       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash6       = "80a0b2154f5b0c87fb7ba82fc32a74807761d038a93d6da45f835417e93af3ef"

  strings:
    $s1 = "k(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";" ascii
    $s2 = "{return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})()" ascii
    $s3 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"L" ascii
    $s4 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"I" ascii
    $s5 = "fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}