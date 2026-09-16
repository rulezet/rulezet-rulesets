rule _20160921_016aab466e10a29b831eb85b27664027_20160921_ad69715850fa_1757 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1  = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(functio" ascii
    $s2  = "(function f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3  = "nction f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s4  = "unction f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){re" ascii
    $s5  = "tion f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTi\";})(),(function f000(){return" ascii
    $s6  = " \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(funct" ascii
    $s7  = "0(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";" ascii
    $s8  = "\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f" ascii
    $s9  = "(function f000(){return \"Uo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s10 = "){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}