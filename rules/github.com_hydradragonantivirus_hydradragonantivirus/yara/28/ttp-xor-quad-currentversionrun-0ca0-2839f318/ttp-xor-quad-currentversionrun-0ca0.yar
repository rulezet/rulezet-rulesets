rule TTP_XOR_QUAD_CurrentVersionRun_0ca0 {
  strings:
    $key_0ca0 = { 5f cf [2] 7b c1 [2] 50 ed [2] 7e cf [2] 6a d4 [2] 65 ce [2] 7b d3 [2] 79 d2 [2] 62 d4 [2] 7e d3 [2] 62 fc }

  condition:
    any of them
}