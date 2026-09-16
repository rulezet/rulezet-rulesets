rule TTP_XOR_QUAD_CurrentVersionRun_759a {
  strings:
    $key_759a = { 26 f5 [2] 02 fb [2] 29 d7 [2] 07 f5 [2] 13 ee [2] 1c f4 [2] 02 e9 [2] 00 e8 [2] 1b ee [2] 07 e9 [2] 1b c6 }

  condition:
    any of them
}