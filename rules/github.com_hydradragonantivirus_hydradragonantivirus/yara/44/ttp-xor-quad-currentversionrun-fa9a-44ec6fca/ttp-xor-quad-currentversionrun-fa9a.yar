rule TTP_XOR_QUAD_CurrentVersionRun_fa9a {
  strings:
    $key_fa9a = { a9 f5 [2] 8d fb [2] a6 d7 [2] 88 f5 [2] 9c ee [2] 93 f4 [2] 8d e9 [2] 8f e8 [2] 94 ee [2] 88 e9 [2] 94 c6 }

  condition:
    any of them
}