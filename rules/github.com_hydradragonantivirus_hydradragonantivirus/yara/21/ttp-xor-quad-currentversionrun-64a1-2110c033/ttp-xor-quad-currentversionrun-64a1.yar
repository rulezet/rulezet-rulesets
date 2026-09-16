rule TTP_XOR_QUAD_CurrentVersionRun_64a1 {
  strings:
    $key_64a1 = { 37 ce [2] 13 c0 [2] 38 ec [2] 16 ce [2] 02 d5 [2] 0d cf [2] 13 d2 [2] 11 d3 [2] 0a d5 [2] 16 d2 [2] 0a fd }

  condition:
    any of them
}