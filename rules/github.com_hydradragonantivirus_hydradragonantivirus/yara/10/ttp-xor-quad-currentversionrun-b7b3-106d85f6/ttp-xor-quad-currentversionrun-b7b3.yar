rule TTP_XOR_QUAD_CurrentVersionRun_b7b3 {
  strings:
    $key_b7b3 = { e4 dc [2] c0 d2 [2] eb fe [2] c5 dc [2] d1 c7 [2] de dd [2] c0 c0 [2] c2 c1 [2] d9 c7 [2] c5 c0 [2] d9 ef }

  condition:
    any of them
}