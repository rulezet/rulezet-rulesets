rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_6ca29d2ebdca_275 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"

  strings:
    $s1  = "return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})()," ascii
    $s2  = ")(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s3  = "turn \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s4  = " f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj" ascii
    $s5  = "(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){re" ascii
    $s6  = "turn \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s7  = "Pt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s8  = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f" ascii
    $s9  = "unction f000(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s10 = "ion f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s11 = "function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s12 = "(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s13 = "n \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s14 = "nction f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s15 = "{return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})" ascii
    $s16 = "f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RVb" ascii
    $s17 = "Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s18 = "l\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s19 = "ion f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s20 = "return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}