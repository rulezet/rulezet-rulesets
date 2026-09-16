rule TTP_XOR_QUAD_CurrentVersionRun_a3c8 {
  strings:
    $key_a3c8 = { f0 a7 [2] d4 a9 [2] ff 85 [2] d1 a7 [2] c5 bc [2] ca a6 [2] d4 bb [2] d6 ba [2] cd bc [2] d1 bb [2] cd 94 }

  condition:
    any of them
}