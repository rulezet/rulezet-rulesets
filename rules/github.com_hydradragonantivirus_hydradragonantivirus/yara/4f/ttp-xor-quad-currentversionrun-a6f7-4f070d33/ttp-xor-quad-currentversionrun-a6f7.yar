rule TTP_XOR_QUAD_CurrentVersionRun_a6f7 {
  strings:
    $key_a6f7 = { f5 98 [2] d1 96 [2] fa ba [2] d4 98 [2] c0 83 [2] cf 99 [2] d1 84 [2] d3 85 [2] c8 83 [2] d4 84 [2] c8 ab }

  condition:
    any of them
}