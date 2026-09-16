rule TTP_XOR_QUAD_CurrentVersionRun_a142 {
  strings:
    $key_a142 = { f2 2d [2] d6 23 [2] fd 0f [2] d3 2d [2] c7 36 [2] c8 2c [2] d6 31 [2] d4 30 [2] cf 36 [2] d3 31 [2] cf 1e }

  condition:
    any of them
}