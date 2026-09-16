rule TTP_XOR_QUAD_CurrentVersionRun_adb6 {
  strings:
    $key_adb6 = { fe d9 [2] da d7 [2] f1 fb [2] df d9 [2] cb c2 [2] c4 d8 [2] da c5 [2] d8 c4 [2] c3 c2 [2] df c5 [2] c3 ea }

  condition:
    any of them
}