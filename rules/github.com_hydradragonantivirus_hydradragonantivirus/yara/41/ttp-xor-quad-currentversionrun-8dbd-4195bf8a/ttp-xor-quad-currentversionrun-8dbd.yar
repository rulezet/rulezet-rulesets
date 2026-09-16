rule TTP_XOR_QUAD_CurrentVersionRun_8dbd {
  strings:
    $key_8dbd = { de d2 [2] fa dc [2] d1 f0 [2] ff d2 [2] eb c9 [2] e4 d3 [2] fa ce [2] f8 cf [2] e3 c9 [2] ff ce [2] e3 e1 }

  condition:
    any of them
}