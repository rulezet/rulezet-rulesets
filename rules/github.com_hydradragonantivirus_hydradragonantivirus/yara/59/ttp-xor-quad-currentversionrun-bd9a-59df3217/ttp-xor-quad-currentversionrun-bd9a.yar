rule TTP_XOR_QUAD_CurrentVersionRun_bd9a {
  strings:
    $key_bd9a = { ee f5 [2] ca fb [2] e1 d7 [2] cf f5 [2] db ee [2] d4 f4 [2] ca e9 [2] c8 e8 [2] d3 ee [2] cf e9 [2] d3 c6 }

  condition:
    any of them
}