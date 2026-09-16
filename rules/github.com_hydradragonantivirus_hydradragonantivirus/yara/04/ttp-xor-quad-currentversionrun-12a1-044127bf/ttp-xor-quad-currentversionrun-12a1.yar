rule TTP_XOR_QUAD_CurrentVersionRun_12a1 {
  strings:
    $key_12a1 = { 41 ce [2] 65 c0 [2] 4e ec [2] 60 ce [2] 74 d5 [2] 7b cf [2] 65 d2 [2] 67 d3 [2] 7c d5 [2] 60 d2 [2] 7c fd }

  condition:
    any of them
}