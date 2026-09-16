rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_a8b3df7e98e8_3643 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash3       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash4       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash5       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash6       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"
    hash7       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"
    hash8       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})" ascii
    $s2 = "e\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s3 = "\"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s4 = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s5 = "Sf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function" ascii
    $s6 = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}