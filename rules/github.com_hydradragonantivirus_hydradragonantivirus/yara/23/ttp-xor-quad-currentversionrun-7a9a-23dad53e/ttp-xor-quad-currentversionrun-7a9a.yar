rule TTP_XOR_QUAD_CurrentVersionRun_7a9a {
  strings:
    $key_7a9a = { 29 f5 [2] 0d fb [2] 26 d7 [2] 08 f5 [2] 1c ee [2] 13 f4 [2] 0d e9 [2] 0f e8 [2] 14 ee [2] 08 e9 [2] 14 c6 }

  condition:
    any of them
}