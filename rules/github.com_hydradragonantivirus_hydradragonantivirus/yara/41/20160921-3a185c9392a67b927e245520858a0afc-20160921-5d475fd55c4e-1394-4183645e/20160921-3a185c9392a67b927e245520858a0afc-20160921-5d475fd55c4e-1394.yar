rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_5d475fd55c4e_1394 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash3       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash4       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash5       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1  = "ion f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return " ascii
    $s2  = "(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){r" ascii
    $s3  = "turn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})()" ascii
    $s4  = "Mz\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functi" ascii
    $s5  = "ction f000(){return \"QDg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return" ascii
    $s6  = "on f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s7  = "function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){ret" ascii
    $s8  = "nction f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s9  = "Dg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function" ascii
    $s10 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000" ascii
    $s11 = "\"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s12 = "{return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(" ascii
    $s13 = "0(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";" ascii
    $s14 = "\"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}