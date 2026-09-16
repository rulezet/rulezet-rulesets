rule TTP_XOR_QUAD_CurrentVersionRun_a6ea {
  strings:
    $key_a6ea = { f5 85 [2] d1 8b [2] fa a7 [2] d4 85 [2] c0 9e [2] cf 84 [2] d1 99 [2] d3 98 [2] c8 9e [2] d4 99 [2] c8 b6 }

  condition:
    any of them
}