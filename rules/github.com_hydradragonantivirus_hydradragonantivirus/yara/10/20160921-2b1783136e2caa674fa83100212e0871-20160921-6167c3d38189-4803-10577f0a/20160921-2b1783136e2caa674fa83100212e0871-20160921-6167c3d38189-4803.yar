rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_4803 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash4       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"

  strings:
    $s1 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s2 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f00" ascii
    $s3 = "00(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";" ascii
    $s4 = "GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s5 = "0(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}