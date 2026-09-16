rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_b062b54e33ac_5019 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash3       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash4       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"
    hash5       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1 = "n \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(fu" ascii
    $s2 = "f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GG" ascii
    $s3 = "0(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";}" ascii
    $s4 = " \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(fu" ascii
    $s5 = "return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}