rule TTP_XOR_QUAD_CurrentVersionRun_adb8 {
  strings:
    $key_adb8 = { fe d7 [2] da d9 [2] f1 f5 [2] df d7 [2] cb cc [2] c4 d6 [2] da cb [2] d8 ca [2] c3 cc [2] df cb [2] c3 e4 }

  condition:
    any of them
}