rule TTP_XOR_QUAD_CurrentVersionRun_179a {
  strings:
    $key_179a = { 44 f5 [2] 60 fb [2] 4b d7 [2] 65 f5 [2] 71 ee [2] 7e f4 [2] 60 e9 [2] 62 e8 [2] 79 ee [2] 65 e9 [2] 79 c6 }

  condition:
    any of them
}