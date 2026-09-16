rule TTP_XOR_QUAD_CurrentVersionRun_0b9a {
  strings:
    $key_0b9a = { 58 f5 [2] 7c fb [2] 57 d7 [2] 79 f5 [2] 6d ee [2] 62 f4 [2] 7c e9 [2] 7e e8 [2] 65 ee [2] 79 e9 [2] 65 c6 }

  condition:
    any of them
}