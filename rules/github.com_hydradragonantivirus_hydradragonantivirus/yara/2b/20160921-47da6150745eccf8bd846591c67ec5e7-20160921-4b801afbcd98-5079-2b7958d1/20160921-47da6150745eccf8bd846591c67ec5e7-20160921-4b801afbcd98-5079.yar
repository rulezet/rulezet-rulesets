rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_4b801afbcd98_5079 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = "tion f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s2 = "})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s3 = "(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Sq\";})" ascii
    $s4 = "0(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})" ascii
    $s5 = "urn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}