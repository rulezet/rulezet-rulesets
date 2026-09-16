rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_3d472332b6f7_2020 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"

  strings:
    $s1 = "f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"S" ascii
    $s2 = "rn \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(),(f" ascii
    $s3 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"TKp\";})(),(function f000(" ascii
    $s4 = "n \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(fu" ascii
    $s5 = " f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s6 = "(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s7 = "00(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s8 = ",(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){" ascii
    $s9 = "GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}