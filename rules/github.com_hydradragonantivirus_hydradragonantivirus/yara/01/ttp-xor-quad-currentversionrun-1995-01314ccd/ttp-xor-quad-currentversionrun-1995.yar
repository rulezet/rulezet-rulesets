rule TTP_XOR_QUAD_CurrentVersionRun_1995 {
  strings:
    $key_1995 = { 4a fa [2] 6e f4 [2] 45 d8 [2] 6b fa [2] 7f e1 [2] 70 fb [2] 6e e6 [2] 6c e7 [2] 77 e1 [2] 6b e6 [2] 77 c9 }

  condition:
    any of them
}