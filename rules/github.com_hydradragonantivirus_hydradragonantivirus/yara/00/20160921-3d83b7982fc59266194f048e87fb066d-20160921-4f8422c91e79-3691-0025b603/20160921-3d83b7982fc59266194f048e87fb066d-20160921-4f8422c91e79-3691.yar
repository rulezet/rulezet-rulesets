rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_4f8422c91e79_3691 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash3       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash4       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"
    hash5       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1 = "unction fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retu" ascii
    $s2 = "ck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\"" ascii
    $s3 = "x\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"DRx\";})(),(function " ascii
    $s4 = "n \"We\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s5 = ",(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s6 = "rn \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}