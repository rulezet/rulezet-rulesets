rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_5496891f48e4_3539 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js, 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash3       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"
    hash4       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash5       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash6       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash7       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1 = "UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(functi" ascii
    $s2 = "tion f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii
    $s3 = "ion f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s4 = "function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){ret" ascii
    $s5 = "000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn" ascii
    $s6 = "(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}