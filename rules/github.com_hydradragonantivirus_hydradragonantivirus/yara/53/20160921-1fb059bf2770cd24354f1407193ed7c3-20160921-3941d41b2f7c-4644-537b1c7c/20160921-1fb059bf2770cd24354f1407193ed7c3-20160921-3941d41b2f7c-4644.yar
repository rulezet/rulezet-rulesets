rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_3941d41b2f7c_4644 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_c10352a0b5ce476f023184a502920234.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash3       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash4       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash5       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash6       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash7       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"
    hash8       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(" ascii
    $s2 = "000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe" ascii
    $s3 = "Qb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(functio" ascii
    $s4 = "function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){ret" ascii
    $s5 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}