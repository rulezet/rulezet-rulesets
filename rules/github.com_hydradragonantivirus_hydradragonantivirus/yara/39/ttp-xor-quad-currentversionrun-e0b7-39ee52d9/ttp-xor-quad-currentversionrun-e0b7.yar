rule TTP_XOR_QUAD_CurrentVersionRun_e0b7 {
  strings:
    $key_e0b7 = { b3 d8 [2] 97 d6 [2] bc fa [2] 92 d8 [2] 86 c3 [2] 89 d9 [2] 97 c4 [2] 95 c5 [2] 8e c3 [2] 92 c4 [2] 8e eb }

  condition:
    any of them
}