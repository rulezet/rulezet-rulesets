rule TTP_XOR_QUAD_CurrentVersionRun_0da1 {
  strings:
    $key_0da1 = { 5e ce [2] 7a c0 [2] 51 ec [2] 7f ce [2] 6b d5 [2] 64 cf [2] 7a d2 [2] 78 d3 [2] 63 d5 [2] 7f d2 [2] 63 fd }

  condition:
    any of them
}