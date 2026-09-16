rule TTP_XOR_QUAD_CurrentVersionRun_f588 {
  strings:
    $key_f588 = { a6 e7 [2] 82 e9 [2] a9 c5 [2] 87 e7 [2] 93 fc [2] 9c e6 [2] 82 fb [2] 80 fa [2] 9b fc [2] 87 fb [2] 9b d4 }

  condition:
    any of them
}