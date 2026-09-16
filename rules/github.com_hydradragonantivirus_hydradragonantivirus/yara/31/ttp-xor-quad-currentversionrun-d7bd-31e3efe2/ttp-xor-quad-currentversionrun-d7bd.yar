rule TTP_XOR_QUAD_CurrentVersionRun_d7bd {
  strings:
    $key_d7bd = { 84 d2 [2] a0 dc [2] 8b f0 [2] a5 d2 [2] b1 c9 [2] be d3 [2] a0 ce [2] a2 cf [2] b9 c9 [2] a5 ce [2] b9 e1 }

  condition:
    any of them
}