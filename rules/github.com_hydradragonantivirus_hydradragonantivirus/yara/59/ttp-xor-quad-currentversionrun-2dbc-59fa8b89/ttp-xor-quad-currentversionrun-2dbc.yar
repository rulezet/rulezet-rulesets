rule TTP_XOR_QUAD_CurrentVersionRun_2dbc {
  strings:
    $key_2dbc = { 7e d3 [2] 5a dd [2] 71 f1 [2] 5f d3 [2] 4b c8 [2] 44 d2 [2] 5a cf [2] 58 ce [2] 43 c8 [2] 5f cf [2] 43 e0 }

  condition:
    any of them
}