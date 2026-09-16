rule TTP_XOR_QUAD_CurrentVersionRun_a173 {
  strings:
    $key_a173 = { f2 1c [2] d6 12 [2] fd 3e [2] d3 1c [2] c7 07 [2] c8 1d [2] d6 00 [2] d4 01 [2] cf 07 [2] d3 00 [2] cf 2f }

  condition:
    any of them
}