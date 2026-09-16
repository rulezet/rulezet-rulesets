rule TTP_XOR_QUAD_CurrentVersionRun_87bc {
  strings:
    $key_87bc = { d4 d3 [2] f0 dd [2] db f1 [2] f5 d3 [2] e1 c8 [2] ee d2 [2] f0 cf [2] f2 ce [2] e9 c8 [2] f5 cf [2] e9 e0 }

  condition:
    any of them
}