rule TTP_XOR_QUAD_CurrentVersionRun_adb5 {
  strings:
    $key_adb5 = { fe da [2] da d4 [2] f1 f8 [2] df da [2] cb c1 [2] c4 db [2] da c6 [2] d8 c7 [2] c3 c1 [2] df c6 [2] c3 e9 }

  condition:
    any of them
}