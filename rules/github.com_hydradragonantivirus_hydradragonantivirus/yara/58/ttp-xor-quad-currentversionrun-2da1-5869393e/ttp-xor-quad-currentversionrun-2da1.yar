rule TTP_XOR_QUAD_CurrentVersionRun_2da1 {
  strings:
    $key_2da1 = { 7e ce [2] 5a c0 [2] 71 ec [2] 5f ce [2] 4b d5 [2] 44 cf [2] 5a d2 [2] 58 d3 [2] 43 d5 [2] 5f d2 [2] 43 fd }

  condition:
    any of them
}