rule TTP_XOR_QUAD_CurrentVersionRun_faa1 {
  strings:
    $key_faa1 = { a9 ce [2] 8d c0 [2] a6 ec [2] 88 ce [2] 9c d5 [2] 93 cf [2] 8d d2 [2] 8f d3 [2] 94 d5 [2] 88 d2 [2] 94 fd }

  condition:
    any of them
}