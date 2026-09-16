rule TTP_XOR_QUAD_CurrentVersionRun_32bd {
  strings:
    $key_32bd = { 61 d2 [2] 45 dc [2] 6e f0 [2] 40 d2 [2] 54 c9 [2] 5b d3 [2] 45 ce [2] 47 cf [2] 5c c9 [2] 40 ce [2] 5c e1 }

  condition:
    any of them
}