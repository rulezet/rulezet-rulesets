rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_4aeb02b393c6_4799 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash3       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"

  strings:
    $s1 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f" ascii
    $s2 = "nction f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s3 = "ion f000(){return \"Rh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s4 = "j\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function" ascii
    $s5 = "{return \"Ml\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Iq\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}