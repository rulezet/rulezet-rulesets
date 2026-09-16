rule TTP_XOR_QUAD_CurrentVersionRun_a64b {
  strings:
    $key_a64b = { f5 24 [2] d1 2a [2] fa 06 [2] d4 24 [2] c0 3f [2] cf 25 [2] d1 38 [2] d3 39 [2] c8 3f [2] d4 38 [2] c8 17 }

  condition:
    any of them
}