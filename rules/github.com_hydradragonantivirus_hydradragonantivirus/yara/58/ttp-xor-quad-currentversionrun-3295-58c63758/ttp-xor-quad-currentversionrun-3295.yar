rule TTP_XOR_QUAD_CurrentVersionRun_3295 {
  strings:
    $key_3295 = { 61 fa [2] 45 f4 [2] 6e d8 [2] 40 fa [2] 54 e1 [2] 5b fb [2] 45 e6 [2] 47 e7 [2] 5c e1 [2] 40 e6 [2] 5c c9 }

  condition:
    any of them
}