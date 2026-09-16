rule TTP_XOR_QUAD_CurrentVersionRun_a61b {
  strings:
    $key_a61b = { f5 74 [2] d1 7a [2] fa 56 [2] d4 74 [2] c0 6f [2] cf 75 [2] d1 68 [2] d3 69 [2] c8 6f [2] d4 68 [2] c8 47 }

  condition:
    any of them
}