rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_4804 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"

  strings:
    $s1 = "Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function" ascii
    $s2 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz\";})" ascii
    $s3 = "urn \"MMz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = " \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s5 = "(function f000(){return \"MMz\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}