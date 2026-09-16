rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_b062b54e33ac_5022 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash3       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash4       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash5       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1 = "{return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})" ascii
    $s2 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000()" ascii
    $s3 = "){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(" ascii
    $s4 = "\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f" ascii
    $s5 = "(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}