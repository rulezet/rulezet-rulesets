rule _20160921_6ad2178e7d047e60c71f9fe1ca457b74_20160921_814eb57aeffc_213 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash2       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash3       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"
    hash4       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"

  strings:
    $s1  = "ction f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){retur" ascii
    $s2  = "f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt" ascii
    $s3  = "\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s4  = "\"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYs\";})(),(func" ascii
    $s5  = "unction f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii
    $s6  = "nction f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s7  = "(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";}" ascii
    $s8  = "unction f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){ret" ascii
    $s9  = "f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s10 = "n \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s11 = "(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s12 = "WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(functio" ascii
    $s13 = ")(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000" ascii
    $s14 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s15 = "eturn \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})()" ascii
    $s16 = " f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TR" ascii
    $s17 = "{return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(" ascii
    $s18 = "return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(" ascii
    $s19 = "rn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(f" ascii
    $s20 = "})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}