rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_b7400937fc4e_1842 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"

  strings:
    $s1  = "nction f000(){return \"DYx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(),(function f000(){retu" ascii
    $s2  = " \"Um\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s3  = "n \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Wb\";})(),(fun" ascii
    $s4  = "eturn \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})()," ascii
    $s5  = "\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f" ascii
    $s6  = "f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa" ascii
    $s7  = "rn \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s8  = "(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";" ascii
    $s9  = ",(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii
    $s10 = "turn \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}