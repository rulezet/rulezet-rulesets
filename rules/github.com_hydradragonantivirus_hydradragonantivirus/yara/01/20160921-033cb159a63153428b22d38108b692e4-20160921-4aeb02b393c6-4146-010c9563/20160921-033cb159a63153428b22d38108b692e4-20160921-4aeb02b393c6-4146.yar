rule _20160921_033cb159a63153428b22d38108b692e4_20160921_4aeb02b393c6_4146 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash3       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash4       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "urn \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s2 = "{return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(" ascii
    $s3 = " f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"D" ascii
    $s4 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s5 = "ion f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}