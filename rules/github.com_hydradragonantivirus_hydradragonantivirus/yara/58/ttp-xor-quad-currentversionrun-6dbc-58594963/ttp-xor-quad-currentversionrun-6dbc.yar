rule TTP_XOR_QUAD_CurrentVersionRun_6dbc {
  strings:
    $key_6dbc = { 3e d3 [2] 1a dd [2] 31 f1 [2] 1f d3 [2] 0b c8 [2] 04 d2 [2] 1a cf [2] 18 ce [2] 03 c8 [2] 1f cf [2] 03 e0 }

  condition:
    any of them
}