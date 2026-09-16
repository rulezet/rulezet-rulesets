rule _20160921_382a0f9b1ae693f8ade627fd2d6a8b52_20160921_54325d6949c5_4940 {
  meta:
    description = "datamaliciousorder - from files 20160921_382a0f9b1ae693f8ade627fd2d6a8b52.js, 20160921_54325d6949c5c03d42a42e11b24dee5c.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4170edc38601b30ac37c9e43a569e4e01000505e73d89702266efb685dc6a8ac"
    hash2       = "0fa3791b48292bf705ed06d701118840e9c87ae1f9ac323fe09b8ad04cedc171"
    hash3       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"

  strings:
    $s1 = "})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f0" ascii
    $s2 = "rn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3 = "0(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";" ascii
    $s4 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(" ascii
    $s5 = "return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}