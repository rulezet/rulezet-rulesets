rule TTP_XOR_QUAD_CurrentVersionRun_4dbc {
  strings:
    $key_4dbc = { 1e d3 [2] 3a dd [2] 11 f1 [2] 3f d3 [2] 2b c8 [2] 24 d2 [2] 3a cf [2] 38 ce [2] 23 c8 [2] 3f cf [2] 23 e0 }

  condition:
    any of them
}