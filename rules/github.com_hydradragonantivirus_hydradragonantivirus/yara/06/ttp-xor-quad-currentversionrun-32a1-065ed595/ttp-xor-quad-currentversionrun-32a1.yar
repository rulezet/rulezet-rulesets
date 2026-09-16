rule TTP_XOR_QUAD_CurrentVersionRun_32a1 {
  strings:
    $key_32a1 = { 61 ce [2] 45 c0 [2] 6e ec [2] 40 ce [2] 54 d5 [2] 5b cf [2] 45 d2 [2] 47 d3 [2] 5c d5 [2] 40 d2 [2] 5c fd }

  condition:
    any of them
}