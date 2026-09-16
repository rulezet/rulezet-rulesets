rule TTP_XOR_QUAD_CurrentVersionRun_a6f4 {
  strings:
    $key_a6f4 = { f5 9b [2] d1 95 [2] fa b9 [2] d4 9b [2] c0 80 [2] cf 9a [2] d1 87 [2] d3 86 [2] c8 80 [2] d4 87 [2] c8 a8 }

  condition:
    any of them
}