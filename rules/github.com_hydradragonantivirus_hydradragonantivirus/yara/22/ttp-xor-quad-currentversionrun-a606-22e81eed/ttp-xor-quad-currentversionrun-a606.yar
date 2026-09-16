rule TTP_XOR_QUAD_CurrentVersionRun_a606 {
  strings:
    $key_a606 = { f5 69 [2] d1 67 [2] fa 4b [2] d4 69 [2] c0 72 [2] cf 68 [2] d1 75 [2] d3 74 [2] c8 72 [2] d4 75 [2] c8 5a }

  condition:
    any of them
}