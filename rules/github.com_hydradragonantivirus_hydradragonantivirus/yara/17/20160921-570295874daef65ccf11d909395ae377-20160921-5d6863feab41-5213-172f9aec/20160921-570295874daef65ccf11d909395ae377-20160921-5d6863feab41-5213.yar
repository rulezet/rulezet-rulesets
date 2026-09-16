rule _20160921_570295874daef65ccf11d909395ae377_20160921_5d6863feab41_5213 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash3       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash4       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "n f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"N" ascii
    $s2 = "n \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(fu" ascii
    $s3 = "return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})()," ascii
    $s4 = "(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){r" ascii
    $s5 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}