rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_5496891f48e4_922 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash3       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash4       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"

  strings:
    $s1  = "n f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s2  = "turn \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})()," ascii
    $s3  = "ction f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s4  = " f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"V" ascii
    $s5  = " \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s6  = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f00" ascii
    $s7  = "urn \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s8  = "\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function " ascii
    $s9  = "){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})" ascii
    $s10 = "){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";}" ascii
    $s11 = "(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";}" ascii
    $s12 = "rn \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s13 = "00(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MDb" ascii
    $s14 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})()," ascii
    $s15 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000" ascii
    $s16 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"RLk\";})(),(function f" ascii
    $s17 = ";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s18 = "00(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\"" ascii
    $s19 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"KDh\";})(),(" ascii
    $s20 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}