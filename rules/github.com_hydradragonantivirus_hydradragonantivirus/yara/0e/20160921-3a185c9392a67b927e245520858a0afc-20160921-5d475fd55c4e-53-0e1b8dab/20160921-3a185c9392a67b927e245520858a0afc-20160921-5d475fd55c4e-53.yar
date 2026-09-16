rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_5d475fd55c4e_53 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash3       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash4       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash5       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash6       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1  = "i\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DAp\";})(),(function" ascii
    $s2  = "eturn \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s3  = "tion f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return" ascii
    $s4  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Qa\";})(),(function f000" ascii
    $s5  = "turn \"TKp\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s6  = "TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(functio" ascii
    $s7  = "})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000" ascii
    $s8  = "Yv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s9  = "return \"DYs\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})()" ascii
    $s10 = ")(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(" ascii
    $s11 = ",(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii
    $s12 = "Gn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s13 = "return \"MKa\";})()];" fullword ascii
    $s14 = "eturn \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})()," ascii
    $s15 = "Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s16 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s17 = " \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(fun" ascii
    $s18 = "(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";}" ascii
    $s19 = "0(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";" ascii
    $s20 = " f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"P" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}