rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_dd666c66b3f1_926 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1  = "000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc" ascii
    $s2  = "ion f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return" ascii
    $s3  = " f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"G" ascii
    $s4  = "00(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s5  = "Sj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s6  = "{return \"IAa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(" ascii
    $s7  = "(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s8  = "),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){" ascii
    $s9  = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Mc\";})(" ascii
    $s10 = "){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})" ascii
    $s11 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s12 = "turn \"Kw\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s13 = "rn \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s14 = "\"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Wb\";})(),(functi" ascii
    $s15 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){retu" ascii
    $s16 = "tion f000(){return \"Wb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s17 = " \"Yi\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(func" ascii
    $s18 = "00(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu" ascii
    $s19 = "n \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(fu" ascii
    $s20 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}