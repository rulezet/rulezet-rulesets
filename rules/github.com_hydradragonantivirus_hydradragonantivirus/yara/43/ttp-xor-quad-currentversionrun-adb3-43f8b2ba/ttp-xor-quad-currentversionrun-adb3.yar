rule TTP_XOR_QUAD_CurrentVersionRun_adb3 {
  strings:
    $key_adb3 = { fe dc [2] da d2 [2] f1 fe [2] df dc [2] cb c7 [2] c4 dd [2] da c0 [2] d8 c1 [2] c3 c7 [2] df c0 [2] c3 ef }

  condition:
    any of them
}