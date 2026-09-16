rule TTP_XOR_QUAD_CurrentVersionRun_a601 {
  strings:
    $key_a601 = { f5 6e [2] d1 60 [2] fa 4c [2] d4 6e [2] c0 75 [2] cf 6f [2] d1 72 [2] d3 73 [2] c8 75 [2] d4 72 [2] c8 5d }

  condition:
    any of them
}