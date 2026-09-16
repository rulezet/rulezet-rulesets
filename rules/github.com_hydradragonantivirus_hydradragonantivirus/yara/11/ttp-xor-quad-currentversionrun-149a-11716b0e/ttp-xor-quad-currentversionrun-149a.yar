rule TTP_XOR_QUAD_CurrentVersionRun_149a {
  strings:
    $key_149a = { 47 f5 [2] 63 fb [2] 48 d7 [2] 66 f5 [2] 72 ee [2] 7d f4 [2] 63 e9 [2] 61 e8 [2] 7a ee [2] 66 e9 [2] 7a c6 }

  condition:
    any of them
}