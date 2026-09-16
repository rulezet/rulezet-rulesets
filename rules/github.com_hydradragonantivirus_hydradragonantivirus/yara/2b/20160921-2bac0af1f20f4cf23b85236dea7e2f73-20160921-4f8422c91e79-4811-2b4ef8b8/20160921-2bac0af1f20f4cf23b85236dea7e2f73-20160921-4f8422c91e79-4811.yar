rule _20160921_2bac0af1f20f4cf23b85236dea7e2f73_20160921_4f8422c91e79_4811 {
  meta:
    description = "datamaliciousorder - from files 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash2       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash3       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash4       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){r" ascii
    $s2 = " \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s3 = "(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck()" ascii
    $s4 = "\"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s5 = "\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}