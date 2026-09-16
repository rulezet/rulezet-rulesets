rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_d1c97b87a698_1644 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1  = ";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s2  = "000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn" ascii
    $s3  = "on f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s4  = "on f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s5  = "return \"BIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})" ascii
    $s6  = "f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn" ascii
    $s7  = "nction f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s8  = "ion f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s9  = "0(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\"" ascii
    $s10 = "rn \"MMz\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s11 = "Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}