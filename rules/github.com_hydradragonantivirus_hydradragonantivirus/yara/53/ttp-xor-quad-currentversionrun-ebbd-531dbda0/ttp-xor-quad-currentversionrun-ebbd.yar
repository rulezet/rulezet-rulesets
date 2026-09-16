rule TTP_XOR_QUAD_CurrentVersionRun_ebbd {
  strings:
    $key_ebbd = { b8 d2 [2] 9c dc [2] b7 f0 [2] 99 d2 [2] 8d c9 [2] 82 d3 [2] 9c ce [2] 9e cf [2] 85 c9 [2] 99 ce [2] 85 e1 }

  condition:
    any of them
}