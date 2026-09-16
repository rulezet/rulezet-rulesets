rule TTP_XOR_QUAD_CurrentVersionRun_a665 {
  strings:
    $key_a665 = { f5 0a [2] d1 04 [2] fa 28 [2] d4 0a [2] c0 11 [2] cf 0b [2] d1 16 [2] d3 17 [2] c8 11 [2] d4 16 [2] c8 39 }

  condition:
    any of them
}