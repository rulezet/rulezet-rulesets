rule TTP_XOR_QUAD_CurrentVersionRun_4b9a {
  strings:
    $key_4b9a = { 18 f5 [2] 3c fb [2] 17 d7 [2] 39 f5 [2] 2d ee [2] 22 f4 [2] 3c e9 [2] 3e e8 [2] 25 ee [2] 39 e9 [2] 25 c6 }

  condition:
    any of them
}