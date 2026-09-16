rule TTP_XOR_QUAD_CurrentVersionRun_b59c {
  strings:
    $key_b59c = { e6 f3 [2] c2 fd [2] e9 d1 [2] c7 f3 [2] d3 e8 [2] dc f2 [2] c2 ef [2] c0 ee [2] db e8 [2] c7 ef [2] db c0 }

  condition:
    any of them
}