rule TTP_XOR_QUAD_CurrentVersionRun_1dbc {
  strings:
    $key_1dbc = { 4e d3 [2] 6a dd [2] 41 f1 [2] 6f d3 [2] 7b c8 [2] 74 d2 [2] 6a cf [2] 68 ce [2] 73 c8 [2] 6f cf [2] 73 e0 }

  condition:
    any of them
}