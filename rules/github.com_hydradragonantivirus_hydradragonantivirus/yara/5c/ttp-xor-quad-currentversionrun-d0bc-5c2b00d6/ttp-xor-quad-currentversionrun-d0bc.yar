rule TTP_XOR_QUAD_CurrentVersionRun_d0bc {
  strings:
    $key_d0bc = { 83 d3 [2] a7 dd [2] 8c f1 [2] a2 d3 [2] b6 c8 [2] b9 d2 [2] a7 cf [2] a5 ce [2] be c8 [2] a2 cf [2] be e0 }

  condition:
    any of them
}