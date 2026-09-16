rule TTP_XOR_QUAD_CurrentVersionRun_f995 {
  strings:
    $key_f995 = { aa fa [2] 8e f4 [2] a5 d8 [2] 8b fa [2] 9f e1 [2] 90 fb [2] 8e e6 [2] 8c e7 [2] 97 e1 [2] 8b e6 [2] 97 c9 }

  condition:
    any of them
}