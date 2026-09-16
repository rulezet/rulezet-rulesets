rule TTP_XOR_QUAD_CurrentVersionRun_f994 {
  strings:
    $key_f994 = { aa fb [2] 8e f5 [2] a5 d9 [2] 8b fb [2] 9f e0 [2] 90 fa [2] 8e e7 [2] 8c e6 [2] 97 e0 [2] 8b e7 [2] 97 c8 }

  condition:
    any of them
}