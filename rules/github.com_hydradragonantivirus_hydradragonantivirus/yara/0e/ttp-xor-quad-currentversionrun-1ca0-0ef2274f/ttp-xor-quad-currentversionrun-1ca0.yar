rule TTP_XOR_QUAD_CurrentVersionRun_1ca0 {
  strings:
    $key_1ca0 = { 4f cf [2] 6b c1 [2] 40 ed [2] 6e cf [2] 7a d4 [2] 75 ce [2] 6b d3 [2] 69 d2 [2] 72 d4 [2] 6e d3 [2] 72 fc }

  condition:
    any of them
}