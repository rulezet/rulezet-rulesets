rule TTP_XOR_QUAD_CurrentVersionRun_009a {
  strings:
    $key_009a = { 53 f5 [2] 77 fb [2] 5c d7 [2] 72 f5 [2] 66 ee [2] 69 f4 [2] 77 e9 [2] 75 e8 [2] 6e ee [2] 72 e9 [2] 6e c6 }

  condition:
    any of them
}