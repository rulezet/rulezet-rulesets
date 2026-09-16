rule TTP_XOR_QUAD_CurrentVersionRun_e7a1 {
  strings:
    $key_e7a1 = { b4 ce [2] 90 c0 [2] bb ec [2] 95 ce [2] 81 d5 [2] 8e cf [2] 90 d2 [2] 92 d3 [2] 89 d5 [2] 95 d2 [2] 89 fd }

  condition:
    any of them
}