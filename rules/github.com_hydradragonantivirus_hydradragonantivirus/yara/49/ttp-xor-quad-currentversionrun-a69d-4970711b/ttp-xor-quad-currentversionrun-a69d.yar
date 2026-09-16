rule TTP_XOR_QUAD_CurrentVersionRun_a69d {
  strings:
    $key_a69d = { f5 f2 [2] d1 fc [2] fa d0 [2] d4 f2 [2] c0 e9 [2] cf f3 [2] d1 ee [2] d3 ef [2] c8 e9 [2] d4 ee [2] c8 c1 }

  condition:
    any of them
}