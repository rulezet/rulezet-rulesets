rule TTP_XOR_QUAD_CurrentVersionRun_2995 {
  strings:
    $key_2995 = { 7a fa [2] 5e f4 [2] 75 d8 [2] 5b fa [2] 4f e1 [2] 40 fb [2] 5e e6 [2] 5c e7 [2] 47 e1 [2] 5b e6 [2] 47 c9 }

  condition:
    any of them
}