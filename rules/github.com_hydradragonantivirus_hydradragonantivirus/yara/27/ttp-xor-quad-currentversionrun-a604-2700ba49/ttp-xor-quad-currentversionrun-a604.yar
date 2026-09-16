rule TTP_XOR_QUAD_CurrentVersionRun_a604 {
  strings:
    $key_a604 = { f5 6b [2] d1 65 [2] fa 49 [2] d4 6b [2] c0 70 [2] cf 6a [2] d1 77 [2] d3 76 [2] c8 70 [2] d4 77 [2] c8 58 }

  condition:
    any of them
}