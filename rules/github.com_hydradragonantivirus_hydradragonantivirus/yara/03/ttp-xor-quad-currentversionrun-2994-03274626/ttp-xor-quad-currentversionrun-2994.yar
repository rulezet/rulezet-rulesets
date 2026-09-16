rule TTP_XOR_QUAD_CurrentVersionRun_2994 {
  strings:
    $key_2994 = { 7a fb [2] 5e f5 [2] 75 d9 [2] 5b fb [2] 4f e0 [2] 40 fa [2] 5e e7 [2] 5c e6 [2] 47 e0 [2] 5b e7 [2] 47 c8 }

  condition:
    any of them
}