rule TTP_XOR_QUAD_CurrentVersionRun_a615 {
  strings:
    $key_a615 = { f5 7a [2] d1 74 [2] fa 58 [2] d4 7a [2] c0 61 [2] cf 7b [2] d1 66 [2] d3 67 [2] c8 61 [2] d4 66 [2] c8 49 }

  condition:
    any of them
}