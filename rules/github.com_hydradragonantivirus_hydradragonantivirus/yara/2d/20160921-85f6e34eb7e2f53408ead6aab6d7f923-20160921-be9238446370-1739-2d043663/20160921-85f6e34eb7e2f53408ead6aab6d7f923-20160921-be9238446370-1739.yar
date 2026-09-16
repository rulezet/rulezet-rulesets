rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_be9238446370_1739 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_be923844637026740bc9e5a4aad21ebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"

  strings:
    $s1  = "t\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s2  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s3  = "0(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s4  = " f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do" ascii
    $s5  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s6  = "unction f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s7  = "Dg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s8  = "urn \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s9  = ",(function f000(){return \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){" ascii
    $s10 = "n \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s11 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Do\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}