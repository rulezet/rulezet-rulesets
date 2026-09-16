rule TTP_XOR_QUAD_CurrentVersionRun_a69a {
  strings:
    $key_a69a = { f5 f5 [2] d1 fb [2] fa d7 [2] d4 f5 [2] c0 ee [2] cf f4 [2] d1 e9 [2] d3 e8 [2] c8 ee [2] d4 e9 [2] c8 c6 }

  condition:
    any of them
}