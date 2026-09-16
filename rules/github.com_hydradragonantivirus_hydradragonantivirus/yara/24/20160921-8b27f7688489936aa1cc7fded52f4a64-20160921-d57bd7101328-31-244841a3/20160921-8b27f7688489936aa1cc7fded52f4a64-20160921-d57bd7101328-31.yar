rule _20160921_8b27f7688489936aa1cc7fded52f4a64_20160921_d57bd7101328_31 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash2       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1  = "unction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s2  = "unction f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s3  = "urn \"PTs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s4  = "ction f000(){return \"DNa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s5  = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f0" ascii
    $s6  = "function f000(){return \"Sq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s7  = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qz\";})(),(function f00" ascii
    $s8  = "function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DAp\";})(),(function f000(){re" ascii
    $s9  = "eturn \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})()" ascii
    $s10 = "Pt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s11 = "{return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s12 = "n f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s13 = "f000(){return \"EZu\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"G" ascii
    $s14 = "on f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s15 = "000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s16 = "000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg" ascii
    $s17 = "\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lo\";})(),(function f0" ascii
    $s18 = "return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})()" ascii
    $s19 = "rn \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s20 = "(){return \"DNa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"XTn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}