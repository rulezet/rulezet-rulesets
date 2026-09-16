rule TTP_XOR_QUAD_CurrentVersionRun_3095 {
  strings:
    $key_3095 = { 63 fa [2] 47 f4 [2] 6c d8 [2] 42 fa [2] 56 e1 [2] 59 fb [2] 47 e6 [2] 45 e7 [2] 5e e1 [2] 42 e6 [2] 5e c9 }

  condition:
    any of them
}