rule TTP_XOR_QUAD_CurrentVersionRun_4ca0 {
  strings:
    $key_4ca0 = { 1f cf [2] 3b c1 [2] 10 ed [2] 3e cf [2] 2a d4 [2] 25 ce [2] 3b d3 [2] 39 d2 [2] 22 d4 [2] 3e d3 [2] 22 fc }

  condition:
    any of them
}