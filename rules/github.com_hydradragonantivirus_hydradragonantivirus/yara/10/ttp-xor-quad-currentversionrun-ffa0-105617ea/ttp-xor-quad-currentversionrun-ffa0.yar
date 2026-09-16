rule TTP_XOR_QUAD_CurrentVersionRun_ffa0 {
  strings:
    $key_ffa0 = { ac cf [2] 88 c1 [2] a3 ed [2] 8d cf [2] 99 d4 [2] 96 ce [2] 88 d3 [2] 8a d2 [2] 91 d4 [2] 8d d3 [2] 91 fc }

  condition:
    any of them
}