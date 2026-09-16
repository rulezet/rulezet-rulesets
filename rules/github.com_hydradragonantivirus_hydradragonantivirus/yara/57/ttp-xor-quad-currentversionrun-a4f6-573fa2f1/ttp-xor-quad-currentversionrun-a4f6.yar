rule TTP_XOR_QUAD_CurrentVersionRun_a4f6 {
  strings:
    $key_a4f6 = { f7 99 [2] d3 97 [2] f8 bb [2] d6 99 [2] c2 82 [2] cd 98 [2] d3 85 [2] d1 84 [2] ca 82 [2] d6 85 [2] ca aa }

  condition:
    any of them
}