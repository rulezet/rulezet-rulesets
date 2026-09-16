rule TTP_XOR_QUAD_CurrentVersionRun_a667 {
  strings:
    $key_a667 = { f5 08 [2] d1 06 [2] fa 2a [2] d4 08 [2] c0 13 [2] cf 09 [2] d1 14 [2] d3 15 [2] c8 13 [2] d4 14 [2] c8 3b }

  condition:
    any of them
}