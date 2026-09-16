rule TTP_XOR_QUAD_CurrentVersionRun_d0bd {
  strings:
    $key_d0bd = { 83 d2 [2] a7 dc [2] 8c f0 [2] a2 d2 [2] b6 c9 [2] b9 d3 [2] a7 ce [2] a5 cf [2] be c9 [2] a2 ce [2] be e1 }

  condition:
    any of them
}