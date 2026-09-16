rule TTP_XOR_QUAD_CurrentVersionRun_5ca0 {
  strings:
    $key_5ca0 = { 0f cf [2] 2b c1 [2] 00 ed [2] 2e cf [2] 3a d4 [2] 35 ce [2] 2b d3 [2] 29 d2 [2] 32 d4 [2] 2e d3 [2] 32 fc }

  condition:
    any of them
}