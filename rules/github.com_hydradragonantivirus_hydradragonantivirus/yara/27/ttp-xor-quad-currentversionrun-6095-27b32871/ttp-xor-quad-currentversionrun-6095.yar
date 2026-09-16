rule TTP_XOR_QUAD_CurrentVersionRun_6095 {
  strings:
    $key_6095 = { 33 fa [2] 17 f4 [2] 3c d8 [2] 12 fa [2] 06 e1 [2] 09 fb [2] 17 e6 [2] 15 e7 [2] 0e e1 [2] 12 e6 [2] 0e c9 }

  condition:
    any of them
}