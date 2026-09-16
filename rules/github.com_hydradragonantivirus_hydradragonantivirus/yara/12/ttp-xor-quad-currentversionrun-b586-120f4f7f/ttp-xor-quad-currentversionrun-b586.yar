rule TTP_XOR_QUAD_CurrentVersionRun_b586 {
  strings:
    $key_b586 = { e6 e9 [2] c2 e7 [2] e9 cb [2] c7 e9 [2] d3 f2 [2] dc e8 [2] c2 f5 [2] c0 f4 [2] db f2 [2] c7 f5 [2] db da }

  condition:
    any of them
}