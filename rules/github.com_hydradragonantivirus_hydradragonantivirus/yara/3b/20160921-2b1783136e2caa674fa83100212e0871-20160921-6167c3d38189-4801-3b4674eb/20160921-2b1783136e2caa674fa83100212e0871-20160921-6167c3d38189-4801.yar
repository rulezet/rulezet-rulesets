rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_4801 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "turn \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})()" ascii
    $s2 = "unction f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s3 = "urn \"DNa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s4 = "00(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\"" ascii
    $s5 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}