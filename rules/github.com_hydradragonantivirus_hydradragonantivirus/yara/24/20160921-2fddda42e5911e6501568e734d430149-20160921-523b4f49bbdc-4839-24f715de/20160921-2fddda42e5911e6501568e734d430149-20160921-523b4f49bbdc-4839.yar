rule _20160921_2fddda42e5911e6501568e734d430149_20160921_523b4f49bbdc_4839 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash3       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash4       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash5       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash6       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1 = "00(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw" ascii
    $s2 = " f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"U" ascii
    $s3 = "unction f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){retu" ascii
    $s4 = "function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s5 = "\"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}