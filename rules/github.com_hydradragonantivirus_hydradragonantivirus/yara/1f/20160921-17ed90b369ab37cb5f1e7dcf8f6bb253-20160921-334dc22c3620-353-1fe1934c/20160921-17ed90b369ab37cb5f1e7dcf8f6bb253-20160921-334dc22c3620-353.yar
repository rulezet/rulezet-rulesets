rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_334dc22c3620_353 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_334dc22c3620386c4119de547e0c0f38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"

  strings:
    $s1  = "nction f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s2  = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s3  = "\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s4  = "f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RP" ascii
    $s5  = "function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii
    $s6  = " \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s7  = "{return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})" ascii
    $s8  = "nction f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii
    $s9  = "unction f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s10 = "})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZGq\";})(),(function f00" ascii
    $s11 = "tion f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s12 = " f000(){return \"Mu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GG" ascii
    $s13 = "f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut" ascii
    $s14 = "Wy\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s15 = "on f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s16 = "unction f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){ret" ascii
    $s17 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s18 = "f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj" ascii
    $s19 = " \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s20 = "Ij\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}