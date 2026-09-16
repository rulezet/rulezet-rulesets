rule TTP_XOR_QUAD_CurrentVersionRun_a660 {
  strings:
    $key_a660 = { f5 0f [2] d1 01 [2] fa 2d [2] d4 0f [2] c0 14 [2] cf 0e [2] d1 13 [2] d3 12 [2] c8 14 [2] d4 13 [2] c8 3c }

  condition:
    any of them
}