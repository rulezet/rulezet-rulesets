rule TTP_XOR_QUAD_CurrentVersionRun_1bbd {
  strings:
    $key_1bbd = { 48 d2 [2] 6c dc [2] 47 f0 [2] 69 d2 [2] 7d c9 [2] 72 d3 [2] 6c ce [2] 6e cf [2] 75 c9 [2] 69 ce [2] 75 e1 }

  condition:
    any of them
}