rule TTP_XOR_QUAD_CurrentVersionRun_4695 {
  strings:
    $key_4695 = { 15 fa [2] 31 f4 [2] 1a d8 [2] 34 fa [2] 20 e1 [2] 2f fb [2] 31 e6 [2] 33 e7 [2] 28 e1 [2] 34 e6 [2] 28 c9 }

  condition:
    any of them
}