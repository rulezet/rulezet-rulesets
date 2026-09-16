rule TTP_XOR_QUAD_CurrentVersionRun_f589 {
  strings:
    $key_f589 = { a6 e6 [2] 82 e8 [2] a9 c4 [2] 87 e6 [2] 93 fd [2] 9c e7 [2] 82 fa [2] 80 fb [2] 9b fd [2] 87 fa [2] 9b d5 }

  condition:
    any of them
}