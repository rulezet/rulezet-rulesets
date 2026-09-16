rule TTP_XOR_QUAD_CurrentVersionRun_a19a {
  strings:
    $key_a19a = { f2 f5 [2] d6 fb [2] fd d7 [2] d3 f5 [2] c7 ee [2] c8 f4 [2] d6 e9 [2] d4 e8 [2] cf ee [2] d3 e9 [2] cf c6 }

  condition:
    any of them
}