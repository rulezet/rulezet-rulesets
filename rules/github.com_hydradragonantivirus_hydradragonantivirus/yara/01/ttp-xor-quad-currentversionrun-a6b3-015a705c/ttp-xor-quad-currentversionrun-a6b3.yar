rule TTP_XOR_QUAD_CurrentVersionRun_a6b3 {
  strings:
    $key_a6b3 = { f5 dc [2] d1 d2 [2] fa fe [2] d4 dc [2] c0 c7 [2] cf dd [2] d1 c0 [2] d3 c1 [2] c8 c7 [2] d4 c0 [2] c8 ef }

  condition:
    any of them
}