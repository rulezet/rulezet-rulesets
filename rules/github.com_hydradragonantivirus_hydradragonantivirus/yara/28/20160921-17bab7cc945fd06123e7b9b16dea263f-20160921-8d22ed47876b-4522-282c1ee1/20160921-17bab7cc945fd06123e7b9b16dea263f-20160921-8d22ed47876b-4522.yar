rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_8d22ed47876b_4522 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash3       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "n \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DNa\";})(),(fu" ascii
    $s2 = "return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})()" ascii
    $s3 = "000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa" ascii
    $s4 = "(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s5 = "\"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}