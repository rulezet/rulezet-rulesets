rule TTP_XOR_QUAD_CurrentVersionRun_3da0 {
  strings:
    $key_3da0 = { 6e cf [2] 4a c1 [2] 61 ed [2] 4f cf [2] 5b d4 [2] 54 ce [2] 4a d3 [2] 48 d2 [2] 53 d4 [2] 4f d3 [2] 53 fc }

  condition:
    any of them
}