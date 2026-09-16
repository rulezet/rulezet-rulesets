rule TTP_XOR_QUAD_CurrentVersionRun_b081 {
  strings:
    $key_b081 = { e3 ee [2] c7 e0 [2] ec cc [2] c2 ee [2] d6 f5 [2] d9 ef [2] c7 f2 [2] c5 f3 [2] de f5 [2] c2 f2 [2] de dd }

  condition:
    any of them
}