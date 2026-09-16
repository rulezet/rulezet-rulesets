rule TTP_XOR_QUAD_CurrentVersionRun_359a {
  strings:
    $key_359a = { 66 f5 [2] 42 fb [2] 69 d7 [2] 47 f5 [2] 53 ee [2] 5c f4 [2] 42 e9 [2] 40 e8 [2] 5b ee [2] 47 e9 [2] 5b c6 }

  condition:
    any of them
}