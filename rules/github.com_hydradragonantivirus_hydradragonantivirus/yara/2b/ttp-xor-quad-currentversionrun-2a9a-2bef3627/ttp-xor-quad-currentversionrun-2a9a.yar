rule TTP_XOR_QUAD_CurrentVersionRun_2a9a {
  strings:
    $key_2a9a = { 79 f5 [2] 5d fb [2] 76 d7 [2] 58 f5 [2] 4c ee [2] 43 f4 [2] 5d e9 [2] 5f e8 [2] 44 ee [2] 58 e9 [2] 44 c6 }

  condition:
    any of them
}