rule TTP_XOR_QUAD_CurrentVersionRun_5ca1 {
  strings:
    $key_5ca1 = { 0f ce [2] 2b c0 [2] 00 ec [2] 2e ce [2] 3a d5 [2] 35 cf [2] 2b d2 [2] 29 d3 [2] 32 d5 [2] 2e d2 [2] 32 fd }

  condition:
    any of them
}