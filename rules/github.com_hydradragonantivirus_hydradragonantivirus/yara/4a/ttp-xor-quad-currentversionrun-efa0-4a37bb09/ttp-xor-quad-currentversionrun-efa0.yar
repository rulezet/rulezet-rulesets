rule TTP_XOR_QUAD_CurrentVersionRun_efa0 {
  strings:
    $key_efa0 = { bc cf [2] 98 c1 [2] b3 ed [2] 9d cf [2] 89 d4 [2] 86 ce [2] 98 d3 [2] 9a d2 [2] 81 d4 [2] 9d d3 [2] 81 fc }

  condition:
    any of them
}