rule TTP_XOR_QUAD_CurrentVersionRun_a170 {
  strings:
    $key_a170 = { f2 1f [2] d6 11 [2] fd 3d [2] d3 1f [2] c7 04 [2] c8 1e [2] d6 03 [2] d4 02 [2] cf 04 [2] d3 03 [2] cf 2c }

  condition:
    any of them
}