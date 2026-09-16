rule TTP_XOR_QUAD_CurrentVersionRun_b587 {
  strings:
    $key_b587 = { e6 e8 [2] c2 e6 [2] e9 ca [2] c7 e8 [2] d3 f3 [2] dc e9 [2] c2 f4 [2] c0 f5 [2] db f3 [2] c7 f4 [2] db db }

  condition:
    any of them
}