rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_73e0cbee1511_1207 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_c979e38640433b8c93e1c145417c85cb.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash3       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"
    hash4       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1  = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s2  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Vf" ascii
    $s3  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"" ascii
    $s4  = "})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuc" ascii
    $s5  = "turn \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(" ascii
    $s6  = "n \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s7  = "eturn \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ai\";})()," ascii
    $s8  = "uck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy" ascii
    $s9  = ";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s10 = "ck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Dc\";" ascii
    $s11 = "\"XCr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s12 = "(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii
    $s13 = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s14 = "return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})()" ascii
    $s15 = "{return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s16 = "\"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xw\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}