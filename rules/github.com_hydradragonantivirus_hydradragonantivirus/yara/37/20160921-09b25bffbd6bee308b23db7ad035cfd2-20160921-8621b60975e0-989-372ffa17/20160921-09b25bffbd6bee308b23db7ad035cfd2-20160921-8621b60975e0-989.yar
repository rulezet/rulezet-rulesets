rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_8621b60975e0_989 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"

  strings:
    $s1  = "nction f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){retu" ascii
    $s2  = "(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";" ascii
    $s3  = "{return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})" ascii
    $s4  = "Kl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(functio" ascii
    $s5  = "n \"OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(f" ascii
    $s6  = "nction f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){ret" ascii
    $s7  = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s8  = "){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(" ascii
    $s9  = "000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa" ascii
    $s10 = "turn \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Rh\";})(),(" ascii
    $s11 = ")(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000" ascii
    $s12 = "(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(),(function f000" ascii
    $s13 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s14 = "),(function f000(){return \"RLk\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii
    $s15 = "n \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s16 = "nction f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return" ascii
    $s17 = "{return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})" ascii
    $s18 = "f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RL" ascii
    $s19 = "000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lo\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}