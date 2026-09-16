rule TTP_XOR_QUAD_CurrentVersionRun_b7f7 {
  strings:
    $key_b7f7 = { e4 98 [2] c0 96 [2] eb ba [2] c5 98 [2] d1 83 [2] de 99 [2] c0 84 [2] c2 85 [2] d9 83 [2] c5 84 [2] d9 ab }

  condition:
    any of them
}