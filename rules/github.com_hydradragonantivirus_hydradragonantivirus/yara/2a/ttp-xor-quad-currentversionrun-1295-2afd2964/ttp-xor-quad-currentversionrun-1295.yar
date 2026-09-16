rule TTP_XOR_QUAD_CurrentVersionRun_1295 {
  strings:
    $key_1295 = { 41 fa [2] 65 f4 [2] 4e d8 [2] 60 fa [2] 74 e1 [2] 7b fb [2] 65 e6 [2] 67 e7 [2] 7c e1 [2] 60 e6 [2] 7c c9 }

  condition:
    any of them
}