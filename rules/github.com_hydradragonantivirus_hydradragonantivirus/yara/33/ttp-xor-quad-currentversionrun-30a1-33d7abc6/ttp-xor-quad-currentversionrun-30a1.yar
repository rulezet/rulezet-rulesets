rule TTP_XOR_QUAD_CurrentVersionRun_30a1 {
  strings:
    $key_30a1 = { 63 ce [2] 47 c0 [2] 6c ec [2] 42 ce [2] 56 d5 [2] 59 cf [2] 47 d2 [2] 45 d3 [2] 5e d5 [2] 42 d2 [2] 5e fd }

  condition:
    any of them
}