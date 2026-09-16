rule TTP_XOR_QUAD_CurrentVersionRun_a3d4 {
  strings:
    $key_a3d4 = { f0 bb [2] d4 b5 [2] ff 99 [2] d1 bb [2] c5 a0 [2] ca ba [2] d4 a7 [2] d6 a6 [2] cd a0 [2] d1 a7 [2] cd 88 }

  condition:
    any of them
}