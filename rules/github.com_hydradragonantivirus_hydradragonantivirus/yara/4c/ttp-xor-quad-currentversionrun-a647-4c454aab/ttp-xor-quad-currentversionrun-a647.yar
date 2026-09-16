rule TTP_XOR_QUAD_CurrentVersionRun_a647 {
  strings:
    $key_a647 = { f5 28 [2] d1 26 [2] fa 0a [2] d4 28 [2] c0 33 [2] cf 29 [2] d1 34 [2] d3 35 [2] c8 33 [2] d4 34 [2] c8 1b }

  condition:
    any of them
}