rule _20160921_4f8422c91e79e3073e201b0b279b1fbb_20160921_73e0cbee1511_102 {
  meta:
    description = "datamaliciousorder - from files 20160921_4f8422c91e79e3073e201b0b279b1fbb.js, 20160921_73e0cbee151147d27e01ecc015f640b4.js, 20160921_c979e38640433b8c93e1c145417c85cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1cc54af4d213d0cd37c81b29d25c29bf00892e3458ef2e236563c69fd58b94a"
    hash2       = "0ad4b632b07e5e4526b874097c116e5183b155ec4b9cf40e3f13ece0ce027344"
    hash3       = "62a468202853ba6a8adb456e8c12b66f8794360c094a85e6d4d2cf43d13a75ce"

  strings:
    $s1  = "eturn \"Xw\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"QTc\";})()," ascii
    $s2  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KV" ascii
    $s3  = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return " ascii
    $s4  = "fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq" ascii
    $s5  = "unction fuck(){return \"Ai\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s6  = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"EHo\";})(),(function fuck()" ascii
    $s7  = "n \"Hs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s8  = "unction fuck(){return \"LGo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s9  = "return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})()" ascii
    $s10 = "(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})" ascii
    $s11 = "uck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";" ascii
    $s12 = "n \"MUs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Et\";})(),(fu" ascii
    $s13 = " \"FJs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s14 = "urn \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s15 = "k(){return \"DAa\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s16 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})()," ascii
    $s17 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return" ascii
    $s18 = "KVh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functi" ascii
    $s19 = "ction fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii
    $s20 = "fuck(){return \"QTc\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}