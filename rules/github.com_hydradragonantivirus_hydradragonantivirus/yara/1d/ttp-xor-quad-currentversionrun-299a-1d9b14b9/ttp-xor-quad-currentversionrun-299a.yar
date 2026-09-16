rule TTP_XOR_QUAD_CurrentVersionRun_299a {
  strings:
    $key_299a = { 7a f5 [2] 5e fb [2] 75 d7 [2] 5b f5 [2] 4f ee [2] 40 f4 [2] 5e e9 [2] 5c e8 [2] 47 ee [2] 5b e9 [2] 47 c6 }

  condition:
    any of them
}