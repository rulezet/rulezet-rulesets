rule TTP_XOR_QUAD_CurrentVersionRun_1da0 {
  strings:
    $key_1da0 = { 4e cf [2] 6a c1 [2] 41 ed [2] 6f cf [2] 7b d4 [2] 74 ce [2] 6a d3 [2] 68 d2 [2] 73 d4 [2] 6f d3 [2] 73 fc }

  condition:
    any of them
}