rule TTP_XOR_QUAD_CurrentVersionRun_e495 {
  strings:
    $key_e495 = { b7 fa [2] 93 f4 [2] b8 d8 [2] 96 fa [2] 82 e1 [2] 8d fb [2] 93 e6 [2] 91 e7 [2] 8a e1 [2] 96 e6 [2] 8a c9 }

  condition:
    any of them
}