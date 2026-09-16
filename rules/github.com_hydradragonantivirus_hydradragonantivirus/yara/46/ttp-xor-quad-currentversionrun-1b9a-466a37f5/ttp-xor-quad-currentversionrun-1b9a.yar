rule TTP_XOR_QUAD_CurrentVersionRun_1b9a {
  strings:
    $key_1b9a = { 48 f5 [2] 6c fb [2] 47 d7 [2] 69 f5 [2] 7d ee [2] 72 f4 [2] 6c e9 [2] 6e e8 [2] 75 ee [2] 69 e9 [2] 75 c6 }

  condition:
    any of them
}