rule TTP_XOR_QUAD_CurrentVersionRun_a6fd {
  strings:
    $key_a6fd = { f5 92 [2] d1 9c [2] fa b0 [2] d4 92 [2] c0 89 [2] cf 93 [2] d1 8e [2] d3 8f [2] c8 89 [2] d4 8e [2] c8 a1 }

  condition:
    any of them
}