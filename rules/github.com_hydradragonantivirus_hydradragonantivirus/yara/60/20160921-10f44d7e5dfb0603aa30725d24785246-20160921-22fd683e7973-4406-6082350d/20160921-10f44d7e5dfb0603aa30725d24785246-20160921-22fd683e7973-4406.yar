rule _20160921_10f44d7e5dfb0603aa30725d24785246_20160921_22fd683e7973_4406 {
  meta:
    description = "datamaliciousorder - from files 20160921_10f44d7e5dfb0603aa30725d24785246.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_ba12dcdd1588a0048542bf1b103073ef.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded66def256e0559ce1d6d20e6f8663edec045a58bb8ef0ec1038fbd91f7c7c1"
    hash2       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash3       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash4       = "18a1f3c65d9893a27783cb78ff5cd36c757196e35be1977f03c68231e20d9b44"
    hash5       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = ";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fu" ascii
    $s2 = "ck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";}" ascii
    $s3 = "})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii
    $s4 = "rn \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(fun" ascii
    $s5 = "{return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}