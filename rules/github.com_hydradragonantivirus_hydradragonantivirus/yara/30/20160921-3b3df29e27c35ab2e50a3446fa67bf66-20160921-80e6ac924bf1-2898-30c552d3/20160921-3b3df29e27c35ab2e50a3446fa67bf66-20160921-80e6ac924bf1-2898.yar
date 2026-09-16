rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_80e6ac924bf1_2898 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash3       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq" ascii
    $s2 = "n \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s3 = "ction f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s4 = "turn \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(" ascii
    $s5 = "),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000()" ascii
    $s6 = " f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"" ascii
    $s7 = " \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}