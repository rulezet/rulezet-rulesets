rule TTP_XOR_QUAD_CurrentVersionRun_b09c {
  strings:
    $key_b09c = { e3 f3 [2] c7 fd [2] ec d1 [2] c2 f3 [2] d6 e8 [2] d9 f2 [2] c7 ef [2] c5 ee [2] de e8 [2] c2 ef [2] de c0 }

  condition:
    any of them
}