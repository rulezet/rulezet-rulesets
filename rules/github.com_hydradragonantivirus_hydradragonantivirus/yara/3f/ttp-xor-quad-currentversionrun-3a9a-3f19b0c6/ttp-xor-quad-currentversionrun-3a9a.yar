rule TTP_XOR_QUAD_CurrentVersionRun_3a9a {
  strings:
    $key_3a9a = { 69 f5 [2] 4d fb [2] 66 d7 [2] 48 f5 [2] 5c ee [2] 53 f4 [2] 4d e9 [2] 4f e8 [2] 54 ee [2] 48 e9 [2] 54 c6 }

  condition:
    any of them
}