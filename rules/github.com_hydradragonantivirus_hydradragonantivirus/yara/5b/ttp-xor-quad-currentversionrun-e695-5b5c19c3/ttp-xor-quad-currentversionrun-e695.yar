rule TTP_XOR_QUAD_CurrentVersionRun_e695 {
  strings:
    $key_e695 = { b5 fa [2] 91 f4 [2] ba d8 [2] 94 fa [2] 80 e1 [2] 8f fb [2] 91 e6 [2] 93 e7 [2] 88 e1 [2] 94 e6 [2] 88 c9 }

  condition:
    any of them
}