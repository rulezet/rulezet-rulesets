rule TTP_XOR_QUAD_CurrentVersionRun_a160 {
  strings:
    $key_a160 = { f2 0f [2] d6 01 [2] fd 2d [2] d3 0f [2] c7 14 [2] c8 0e [2] d6 13 [2] d4 12 [2] cf 14 [2] d3 13 [2] cf 3c }

  condition:
    any of them
}