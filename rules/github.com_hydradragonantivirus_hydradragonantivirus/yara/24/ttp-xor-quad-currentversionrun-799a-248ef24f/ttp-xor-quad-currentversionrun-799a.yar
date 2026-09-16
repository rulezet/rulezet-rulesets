rule TTP_XOR_QUAD_CurrentVersionRun_799a {
  strings:
    $key_799a = { 2a f5 [2] 0e fb [2] 25 d7 [2] 0b f5 [2] 1f ee [2] 10 f4 [2] 0e e9 [2] 0c e8 [2] 17 ee [2] 0b e9 [2] 17 c6 }

  condition:
    any of them
}