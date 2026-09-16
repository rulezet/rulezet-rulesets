rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_6d18600f3019_2720 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"

  strings:
    $s1 = "Nx\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function" ascii
    $s2 = "{return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(" ascii
    $s3 = "eturn \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})()," ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";}" ascii
    $s5 = "function f000(){return \"DYx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(),(function f000(){re" ascii
    $s6 = "turn \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})()," ascii
    $s7 = "n f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}