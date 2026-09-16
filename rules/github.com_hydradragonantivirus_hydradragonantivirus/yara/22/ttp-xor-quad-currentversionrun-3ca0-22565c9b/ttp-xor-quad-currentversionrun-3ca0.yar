rule TTP_XOR_QUAD_CurrentVersionRun_3ca0 {
  strings:
    $key_3ca0 = { 6f cf [2] 4b c1 [2] 60 ed [2] 4e cf [2] 5a d4 [2] 55 ce [2] 4b d3 [2] 49 d2 [2] 52 d4 [2] 4e d3 [2] 52 fc }

  condition:
    any of them
}