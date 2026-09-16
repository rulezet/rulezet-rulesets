rule TTP_XOR_QUAD_CurrentVersionRun_f495 {
  strings:
    $key_f495 = { a7 fa [2] 83 f4 [2] a8 d8 [2] 86 fa [2] 92 e1 [2] 9d fb [2] 83 e6 [2] 81 e7 [2] 9a e1 [2] 86 e6 [2] 9a c9 }

  condition:
    any of them
}