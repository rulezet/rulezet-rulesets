rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_63def3fff7f1_326 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"

  strings:
    $s1  = "eturn \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})()," ascii
    $s2  = "ion f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s3  = " f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZF" ascii
    $s4  = "ion f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5  = "urn \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(" ascii
    $s6  = "OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(functio" ascii
    $s7  = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s8  = "return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})()" ascii
    $s9  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTs\"" ascii
    $s10 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f00" ascii
    $s11 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s12 = "BMj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s13 = "n f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s14 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000" ascii
    $s15 = "return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s16 = "000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc" ascii
    $s17 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii
    $s18 = "urn \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTs\";})(),(f" ascii
    $s19 = "\"Ot\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Wb\";})(),(functio" ascii
    $s20 = "n \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}