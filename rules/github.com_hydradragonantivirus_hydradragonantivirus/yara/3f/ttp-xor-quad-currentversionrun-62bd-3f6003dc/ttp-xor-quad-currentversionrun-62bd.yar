rule TTP_XOR_QUAD_CurrentVersionRun_62bd {
  strings:
    $key_62bd = { 31 d2 [2] 15 dc [2] 3e f0 [2] 10 d2 [2] 04 c9 [2] 0b d3 [2] 15 ce [2] 17 cf [2] 0c c9 [2] 10 ce [2] 0c e1 }

  condition:
    any of them
}