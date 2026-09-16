rule TTP_XOR_QUAD_CurrentVersionRun_059a {
  strings:
    $key_059a = { 56 f5 [2] 72 fb [2] 59 d7 [2] 77 f5 [2] 63 ee [2] 6c f4 [2] 72 e9 [2] 70 e8 [2] 6b ee [2] 77 e9 [2] 6b c6 }

  condition:
    any of them
}