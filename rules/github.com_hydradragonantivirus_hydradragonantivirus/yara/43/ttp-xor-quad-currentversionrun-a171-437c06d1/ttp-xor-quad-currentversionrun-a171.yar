rule TTP_XOR_QUAD_CurrentVersionRun_a171 {
  strings:
    $key_a171 = { f2 1e [2] d6 10 [2] fd 3c [2] d3 1e [2] c7 05 [2] c8 1f [2] d6 02 [2] d4 03 [2] cf 05 [2] d3 02 [2] cf 2d }

  condition:
    any of them
}