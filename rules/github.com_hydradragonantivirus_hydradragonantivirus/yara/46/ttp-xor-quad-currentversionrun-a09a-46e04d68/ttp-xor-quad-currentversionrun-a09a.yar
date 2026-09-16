rule TTP_XOR_QUAD_CurrentVersionRun_a09a {
  strings:
    $key_a09a = { f3 f5 [2] d7 fb [2] fc d7 [2] d2 f5 [2] c6 ee [2] c9 f4 [2] d7 e9 [2] d5 e8 [2] ce ee [2] d2 e9 [2] ce c6 }

  condition:
    any of them
}