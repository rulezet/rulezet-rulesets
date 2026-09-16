rule TTP_XOR_QUAD_CurrentVersionRun_629a {
  strings:
    $key_629a = { 31 f5 [2] 15 fb [2] 3e d7 [2] 10 f5 [2] 04 ee [2] 0b f4 [2] 15 e9 [2] 17 e8 [2] 0c ee [2] 10 e9 [2] 0c c6 }

  condition:
    any of them
}