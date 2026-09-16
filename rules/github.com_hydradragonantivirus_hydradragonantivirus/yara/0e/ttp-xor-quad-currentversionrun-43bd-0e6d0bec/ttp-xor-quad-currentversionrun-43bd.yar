rule TTP_XOR_QUAD_CurrentVersionRun_43bd {
  strings:
    $key_43bd = { 10 d2 [2] 34 dc [2] 1f f0 [2] 31 d2 [2] 25 c9 [2] 2a d3 [2] 34 ce [2] 36 cf [2] 2d c9 [2] 31 ce [2] 2d e1 }

  condition:
    any of them
}