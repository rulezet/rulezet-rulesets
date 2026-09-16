rule TTP_XOR_QUAD_CurrentVersionRun_fbbd {
  strings:
    $key_fbbd = { a8 d2 [2] 8c dc [2] a7 f0 [2] 89 d2 [2] 9d c9 [2] 92 d3 [2] 8c ce [2] 8e cf [2] 95 c9 [2] 89 ce [2] 95 e1 }

  condition:
    any of them
}