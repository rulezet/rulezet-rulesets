rule _20160921_802181e3d75c3e2d045cebba97849683_20160921_d74d6a32efd0_1415 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1  = "eturn \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})()," ascii
    $s2  = ")(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s3  = "(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii
    $s4  = " f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GG" ascii
    $s5  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s6  = "0(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";" ascii
    $s7  = "(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";}" ascii
    $s8  = " f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"R" ascii
    $s9  = " f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Fs" ascii
    $s10 = "unction f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii
    $s11 = "\"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s12 = "(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s13 = "nction f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s14 = "f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}