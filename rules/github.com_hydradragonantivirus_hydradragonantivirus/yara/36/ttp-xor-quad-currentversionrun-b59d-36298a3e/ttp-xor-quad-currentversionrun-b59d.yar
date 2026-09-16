rule TTP_XOR_QUAD_CurrentVersionRun_b59d {
  strings:
    $key_b59d = { e6 f2 [2] c2 fc [2] e9 d0 [2] c7 f2 [2] d3 e9 [2] dc f3 [2] c2 ee [2] c0 ef [2] db e9 [2] c7 ee [2] db c1 }

  condition:
    any of them
}