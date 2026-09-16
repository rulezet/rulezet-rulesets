rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_702e8529103b_5197 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash3       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash4       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1 = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";" ascii
    $s2 = "n \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s3 = "ion f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return " ascii
    $s4 = "nction f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){ret" ascii
    $s5 = "return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}