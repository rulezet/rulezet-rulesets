rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_68d4a1cff7c2_4224 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash3       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){ret" ascii
    $s2 = "ion f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return " ascii
    $s3 = "\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s4 = "{return \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})" ascii
    $s5 = "ction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}