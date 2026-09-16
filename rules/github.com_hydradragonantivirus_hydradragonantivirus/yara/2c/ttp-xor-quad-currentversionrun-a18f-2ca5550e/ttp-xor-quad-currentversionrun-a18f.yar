rule TTP_XOR_QUAD_CurrentVersionRun_a18f {
  strings:
    $key_a18f = { f2 e0 [2] d6 ee [2] fd c2 [2] d3 e0 [2] c7 fb [2] c8 e1 [2] d6 fc [2] d4 fd [2] cf fb [2] d3 fc [2] cf d3 }

  condition:
    any of them
}