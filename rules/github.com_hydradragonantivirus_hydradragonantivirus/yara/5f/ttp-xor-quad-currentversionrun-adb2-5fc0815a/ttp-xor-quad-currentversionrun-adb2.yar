rule TTP_XOR_QUAD_CurrentVersionRun_adb2 {
  strings:
    $key_adb2 = { fe dd [2] da d3 [2] f1 ff [2] df dd [2] cb c6 [2] c4 dc [2] da c1 [2] d8 c0 [2] c3 c6 [2] df c1 [2] c3 ee }

  condition:
    any of them
}