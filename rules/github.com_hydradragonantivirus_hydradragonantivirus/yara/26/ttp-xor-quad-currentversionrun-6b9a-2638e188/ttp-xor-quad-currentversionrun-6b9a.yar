rule TTP_XOR_QUAD_CurrentVersionRun_6b9a {
  strings:
    $key_6b9a = { 38 f5 [2] 1c fb [2] 37 d7 [2] 19 f5 [2] 0d ee [2] 02 f4 [2] 1c e9 [2] 1e e8 [2] 05 ee [2] 19 e9 [2] 05 c6 }

  condition:
    any of them
}