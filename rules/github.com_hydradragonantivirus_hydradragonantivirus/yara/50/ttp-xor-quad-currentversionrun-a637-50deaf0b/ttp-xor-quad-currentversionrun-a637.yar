rule TTP_XOR_QUAD_CurrentVersionRun_a637 {
  strings:
    $key_a637 = { f5 58 [2] d1 56 [2] fa 7a [2] d4 58 [2] c0 43 [2] cf 59 [2] d1 44 [2] d3 45 [2] c8 43 [2] d4 44 [2] c8 6b }

  condition:
    any of them
}