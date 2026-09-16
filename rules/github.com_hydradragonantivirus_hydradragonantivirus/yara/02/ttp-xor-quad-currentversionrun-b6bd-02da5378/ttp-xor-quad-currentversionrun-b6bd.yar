rule TTP_XOR_QUAD_CurrentVersionRun_b6bd {
  strings:
    $key_b6bd = { e5 d2 [2] c1 dc [2] ea f0 [2] c4 d2 [2] d0 c9 [2] df d3 [2] c1 ce [2] c3 cf [2] d8 c9 [2] c4 ce [2] d8 e1 }

  condition:
    any of them
}