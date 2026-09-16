rule _20160921_2fddda42e5911e6501568e734d430149_20160921_6748b4ad3c83_4834 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash3       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash4       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash5       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash6       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash7       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"

  strings:
    $s1 = ")(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000" ascii
    $s2 = "return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})()" ascii
    $s3 = "000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa" ascii
    $s4 = "on f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s5 = "urn \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}