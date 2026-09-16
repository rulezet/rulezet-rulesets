rule TTP_XOR_QUAD_CurrentVersionRun_96bc {
  strings:
    $key_96bc = { c5 d3 [2] e1 dd [2] ca f1 [2] e4 d3 [2] f0 c8 [2] ff d2 [2] e1 cf [2] e3 ce [2] f8 c8 [2] e4 cf [2] f8 e0 }

  condition:
    any of them
}