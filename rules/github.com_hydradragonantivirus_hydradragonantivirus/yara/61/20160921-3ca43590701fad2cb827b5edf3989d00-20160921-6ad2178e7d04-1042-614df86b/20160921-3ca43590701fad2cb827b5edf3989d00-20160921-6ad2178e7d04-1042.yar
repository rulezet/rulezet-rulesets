rule _20160921_3ca43590701fad2cb827b5edf3989d00_20160921_6ad2178e7d04_1042 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash2       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"

  strings:
    $s1  = "Kl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s2  = "nction f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){retu" ascii
    $s3  = "000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi" ascii
    $s4  = "0(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s5  = "ion f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s6  = "n \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s7  = "0(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";" ascii
    $s8  = "f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe" ascii
    $s9  = "GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"ZFe\";})(),(functi" ascii
    $s10 = ",(function f000(){return \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s11 = "QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(functi" ascii
    $s12 = "f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe" ascii
    $s13 = "(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){r" ascii
    $s14 = "d\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(functio" ascii
    $s15 = "RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s16 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii
    $s17 = "00(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu" ascii
    $s18 = "eturn \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}