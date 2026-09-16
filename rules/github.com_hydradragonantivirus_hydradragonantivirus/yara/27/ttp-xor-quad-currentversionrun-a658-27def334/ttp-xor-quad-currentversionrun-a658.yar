rule TTP_XOR_QUAD_CurrentVersionRun_a658 {
  strings:
    $key_a658 = { f5 37 [2] d1 39 [2] fa 15 [2] d4 37 [2] c0 2c [2] cf 36 [2] d1 2b [2] d3 2a [2] c8 2c [2] d4 2b [2] c8 04 }

  condition:
    any of them
}