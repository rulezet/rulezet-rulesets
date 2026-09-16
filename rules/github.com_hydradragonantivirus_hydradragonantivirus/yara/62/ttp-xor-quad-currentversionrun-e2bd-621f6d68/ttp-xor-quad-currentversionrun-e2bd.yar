rule TTP_XOR_QUAD_CurrentVersionRun_e2bd {
  strings:
    $key_e2bd = { b1 d2 [2] 95 dc [2] be f0 [2] 90 d2 [2] 84 c9 [2] 8b d3 [2] 95 ce [2] 97 cf [2] 8c c9 [2] 90 ce [2] 8c e1 }

  condition:
    any of them
}