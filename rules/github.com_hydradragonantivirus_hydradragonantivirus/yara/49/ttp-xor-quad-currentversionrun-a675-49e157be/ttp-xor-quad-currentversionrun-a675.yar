rule TTP_XOR_QUAD_CurrentVersionRun_a675 {
  strings:
    $key_a675 = { f5 1a [2] d1 14 [2] fa 38 [2] d4 1a [2] c0 01 [2] cf 1b [2] d1 06 [2] d3 07 [2] c8 01 [2] d4 06 [2] c8 29 }

  condition:
    any of them
}