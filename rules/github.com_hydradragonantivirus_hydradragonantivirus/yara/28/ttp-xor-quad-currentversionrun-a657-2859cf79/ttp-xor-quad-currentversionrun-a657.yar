rule TTP_XOR_QUAD_CurrentVersionRun_a657 {
  strings:
    $key_a657 = { f5 38 [2] d1 36 [2] fa 1a [2] d4 38 [2] c0 23 [2] cf 39 [2] d1 24 [2] d3 25 [2] c8 23 [2] d4 24 [2] c8 0b }

  condition:
    any of them
}