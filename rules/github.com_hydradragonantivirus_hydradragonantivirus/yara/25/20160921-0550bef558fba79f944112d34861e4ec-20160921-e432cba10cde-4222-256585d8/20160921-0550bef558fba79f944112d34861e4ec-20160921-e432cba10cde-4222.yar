rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_e432cba10cde_4222 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_e432cba10cde369693d6b125dda112c7.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"
    hash3       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = "00(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s2 = "(function f000(){return \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s3 = "(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){r" ascii
    $s4 = "00(){return \"Tb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\"" ascii
    $s5 = " f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}