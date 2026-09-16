rule _20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7_20160921_3a89132c2088_2838 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4c1d98d0b8022ca5527a8e6d96e6e7.js, 20160921_3a89132c20887c3360a3708984b884fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65be7c1c5efef8255d7094d95251c12de72303024061cff2152d54a244a049f0"
    hash2       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"

  strings:
    $s1 = "tion f000(){return \"MKa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return" ascii
    $s2 = "rn \"IAa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})(),(fu" ascii
    $s3 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s4 = "(){return \"KDh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s5 = "\"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s6 = "on f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii
    $s7 = "){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}