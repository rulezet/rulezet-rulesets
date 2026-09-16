rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_073b3e31779f_798 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_73b5a50d06622b8411077815f2717627.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash3       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash4       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash5       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash6       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1  = "00(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\"" ascii
    $s2  = "turn \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(" ascii
    $s3  = " f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"" ascii
    $s4  = "n f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"" ascii
    $s5  = "nction f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s6  = "turn \"PTi\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s7  = "Gn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s8  = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sv\";" ascii
    $s9  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(fu" ascii
    $s10 = "00(){return \"KIc\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp" ascii
    $s11 = "Ys\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s12 = "function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){r" ascii
    $s13 = "Br\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(functio" ascii
    $s14 = "{return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"RPt\";})(" ascii
    $s15 = "000(){return \"IAa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn" ascii
    $s16 = "f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s17 = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs" ascii
    $s18 = "{return \"PTi\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(" ascii
    $s19 = "\"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(functi" ascii
    $s20 = "tion f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}