rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_9d32b55f93b8_375 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash3       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash4       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1  = "n f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s2  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MMz\";})(),(function f0" ascii
    $s3  = "(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s4  = "ion f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s5  = "000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s6  = "){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";" ascii
    $s7  = "ction f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){retur" ascii
    $s8  = "){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(" ascii
    $s9  = "tion f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s10 = " \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s11 = "eturn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})()," ascii
    $s12 = "(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){re" ascii
    $s13 = ",(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){r" ascii
    $s14 = "ion f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s15 = "Kl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s16 = "return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(" ascii
    $s17 = "\"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(funct" ascii
    $s18 = "00(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Lo\"" ascii
    $s19 = "turn \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})()," ascii
    $s20 = "000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}