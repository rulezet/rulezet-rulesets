rule TTP_XOR_QUAD_CurrentVersionRun_b69c {
  strings:
    $key_b69c = { e5 f3 [2] c1 fd [2] ea d1 [2] c4 f3 [2] d0 e8 [2] df f2 [2] c1 ef [2] c3 ee [2] d8 e8 [2] c4 ef [2] d8 c0 }

  condition:
    any of them
}