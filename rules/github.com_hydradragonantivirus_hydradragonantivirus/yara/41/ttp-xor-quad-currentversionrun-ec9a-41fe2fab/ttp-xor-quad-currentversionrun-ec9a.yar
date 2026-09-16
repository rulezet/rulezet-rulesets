rule TTP_XOR_QUAD_CurrentVersionRun_ec9a {
  strings:
    $key_ec9a = { bf f5 [2] 9b fb [2] b0 d7 [2] 9e f5 [2] 8a ee [2] 85 f4 [2] 9b e9 [2] 99 e8 [2] 82 ee [2] 9e e9 [2] 82 c6 }

  condition:
    any of them
}