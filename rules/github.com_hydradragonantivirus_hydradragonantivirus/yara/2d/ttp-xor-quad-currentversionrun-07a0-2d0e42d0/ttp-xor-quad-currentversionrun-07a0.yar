rule TTP_XOR_QUAD_CurrentVersionRun_07a0 {
  strings:
    $key_07a0 = { 54 cf [2] 70 c1 [2] 5b ed [2] 75 cf [2] 61 d4 [2] 6e ce [2] 70 d3 [2] 72 d2 [2] 69 d4 [2] 75 d3 [2] 69 fc }

  condition:
    any of them
}