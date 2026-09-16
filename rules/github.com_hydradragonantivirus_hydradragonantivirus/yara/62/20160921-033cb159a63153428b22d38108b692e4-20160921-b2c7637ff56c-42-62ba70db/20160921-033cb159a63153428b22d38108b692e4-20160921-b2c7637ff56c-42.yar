rule _20160921_033cb159a63153428b22d38108b692e4_20160921_b2c7637ff56c_42 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"

  strings:
    $s1  = "rn \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s2  = "})(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s3  = "n f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"M" ascii
    $s4  = "(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(" ascii
    $s5  = "n f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"L" ascii
    $s6  = "00(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Nx\";" ascii
    $s7  = "turn \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s8  = "(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})" ascii
    $s9  = "f000(){return \"PTi\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"D" ascii
    $s10 = "Na\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s11 = "urn \"ZIi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OUx\";})(),(" ascii
    $s12 = "0(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";" ascii
    $s13 = "(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"ZIi\";" ascii
    $s14 = "unction f000(){return \"Yv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s15 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){" ascii
    $s16 = "(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})" ascii
    $s17 = "000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"RPt" ascii
    $s18 = "(){return \"PTs\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";}" ascii
    $s19 = "0(){return \"Lp\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";" ascii
    $s20 = "unction f000(){return \"TKp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}