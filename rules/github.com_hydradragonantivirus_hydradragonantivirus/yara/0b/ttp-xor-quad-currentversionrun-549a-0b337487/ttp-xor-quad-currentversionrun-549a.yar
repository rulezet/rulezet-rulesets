rule TTP_XOR_QUAD_CurrentVersionRun_549a {
  strings:
    $key_549a = { 07 f5 [2] 23 fb [2] 08 d7 [2] 26 f5 [2] 32 ee [2] 3d f4 [2] 23 e9 [2] 21 e8 [2] 3a ee [2] 26 e9 [2] 3a c6 }

  condition:
    any of them
}