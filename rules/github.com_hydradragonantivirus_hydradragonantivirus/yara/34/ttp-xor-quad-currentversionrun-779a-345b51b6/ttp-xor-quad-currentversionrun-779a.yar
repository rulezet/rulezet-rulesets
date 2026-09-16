rule TTP_XOR_QUAD_CurrentVersionRun_779a {
  strings:
    $key_779a = { 24 f5 [2] 00 fb [2] 2b d7 [2] 05 f5 [2] 11 ee [2] 1e f4 [2] 00 e9 [2] 02 e8 [2] 19 ee [2] 05 e9 [2] 19 c6 }

  condition:
    any of them
}