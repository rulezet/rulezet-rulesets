rule TTP_XOR_QUAD_CurrentVersionRun_7b9a {
  strings:
    $key_7b9a = { 28 f5 [2] 0c fb [2] 27 d7 [2] 09 f5 [2] 1d ee [2] 12 f4 [2] 0c e9 [2] 0e e8 [2] 15 ee [2] 09 e9 [2] 15 c6 }

  condition:
    any of them
}