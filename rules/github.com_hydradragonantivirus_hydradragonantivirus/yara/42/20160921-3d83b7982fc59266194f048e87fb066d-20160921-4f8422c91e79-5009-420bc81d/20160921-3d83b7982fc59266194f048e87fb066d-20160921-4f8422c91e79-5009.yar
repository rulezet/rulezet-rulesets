rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_4f8422c91e79_5009 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_c979e38640433b8c93e1c145417c85cb.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash3       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash4       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"
    hash5       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash6       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"
    hash7       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s2 = "n fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s3 = "(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s4 = "ck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}