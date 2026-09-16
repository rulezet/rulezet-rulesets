rule _20160921_46b3ab412369507850a916abad1e6bf0_20160921_a3256642bcc1_1113 {
  meta:
    description = "datamaliciousorder - from files 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1  = "00(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg" ascii
    $s2  = ",(function f000(){return \"Sj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){re" ascii
    $s3  = ")(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(" ascii
    $s4  = "f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GG" ascii
    $s5  = "0(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";" ascii
    $s6  = "){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";" ascii
    $s7  = "n \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s8  = "eturn \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(" ascii
    $s9  = "(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KDh\";})" ascii
    $s10 = "Gn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s11 = "(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){" ascii
    $s12 = "0(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";" ascii
    $s13 = " \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fun" ascii
    $s14 = "\"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(functi" ascii
    $s15 = "tion f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s16 = "\"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s17 = "000(){return \"RPt\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}