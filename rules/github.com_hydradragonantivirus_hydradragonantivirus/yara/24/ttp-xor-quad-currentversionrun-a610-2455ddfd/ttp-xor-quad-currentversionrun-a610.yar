rule TTP_XOR_QUAD_CurrentVersionRun_a610 {
  strings:
    $key_a610 = { f5 7f [2] d1 71 [2] fa 5d [2] d4 7f [2] c0 64 [2] cf 7e [2] d1 63 [2] d3 62 [2] c8 64 [2] d4 63 [2] c8 4c }

  condition:
    any of them
}