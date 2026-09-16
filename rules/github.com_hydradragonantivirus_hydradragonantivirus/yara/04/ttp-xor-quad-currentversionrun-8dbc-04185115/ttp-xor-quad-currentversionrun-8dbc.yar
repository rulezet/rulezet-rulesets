rule TTP_XOR_QUAD_CurrentVersionRun_8dbc {
  strings:
    $key_8dbc = { de d3 [2] fa dd [2] d1 f1 [2] ff d3 [2] eb c8 [2] e4 d2 [2] fa cf [2] f8 ce [2] e3 c8 [2] ff cf [2] e3 e0 }

  condition:
    any of them
}