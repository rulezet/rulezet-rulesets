rule TTP_XOR_QUAD_CurrentVersionRun_b09a {
  strings:
    $key_b09a = { e3 f5 [2] c7 fb [2] ec d7 [2] c2 f5 [2] d6 ee [2] d9 f4 [2] c7 e9 [2] c5 e8 [2] de ee [2] c2 e9 [2] de c6 }

  condition:
    any of them
}