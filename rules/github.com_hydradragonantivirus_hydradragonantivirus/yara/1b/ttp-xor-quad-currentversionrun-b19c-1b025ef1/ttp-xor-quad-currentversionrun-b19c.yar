rule TTP_XOR_QUAD_CurrentVersionRun_b19c {
  strings:
    $key_b19c = { e2 f3 [2] c6 fd [2] ed d1 [2] c3 f3 [2] d7 e8 [2] d8 f2 [2] c6 ef [2] c4 ee [2] df e8 [2] c3 ef [2] df c0 }

  condition:
    any of them
}