rule TTP_XOR_QUAD_CurrentVersionRun_a654 {
  strings:
    $key_a654 = { f5 3b [2] d1 35 [2] fa 19 [2] d4 3b [2] c0 20 [2] cf 3a [2] d1 27 [2] d3 26 [2] c8 20 [2] d4 27 [2] c8 08 }

  condition:
    any of them
}