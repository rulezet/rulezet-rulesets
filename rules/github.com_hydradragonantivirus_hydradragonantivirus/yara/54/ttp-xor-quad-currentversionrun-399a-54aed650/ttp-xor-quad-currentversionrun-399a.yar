rule TTP_XOR_QUAD_CurrentVersionRun_399a {
  strings:
    $key_399a = { 6a f5 [2] 4e fb [2] 65 d7 [2] 4b f5 [2] 5f ee [2] 50 f4 [2] 4e e9 [2] 4c e8 [2] 57 ee [2] 4b e9 [2] 57 c6 }

  condition:
    any of them
}