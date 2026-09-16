rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_10f44d7e5dfb_317 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash3       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash4       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"

  strings:
    $s1  = "ck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu" ascii
    $s2  = " \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s3  = "unction fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){ret" ascii
    $s4  = "k(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf" ascii
    $s5  = "){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})" ascii
    $s6  = "(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"We\";}" ascii
    $s7  = "ck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm" ascii
    $s8  = "ck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo" ascii
    $s9  = "n fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii
    $s10 = "ion fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s11 = "\"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(func" ascii
    $s12 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s13 = "uck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd" ascii
    $s14 = "Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s15 = "UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s16 = " \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s17 = "Bg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s18 = "k(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn" ascii
    $s19 = "){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})" ascii
    $s20 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"N" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}