rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_85f6e34eb7e2_4223 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash3       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash4       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii
    $s3 = " \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(func" ascii
    $s4 = "0(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s5 = "nction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}