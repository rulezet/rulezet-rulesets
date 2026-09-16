rule TTP_XOR_QUAD_CurrentVersionRun_11a0 {
  strings:
    $key_11a0 = { 42 cf [2] 66 c1 [2] 4d ed [2] 63 cf [2] 77 d4 [2] 78 ce [2] 66 d3 [2] 64 d2 [2] 7f d4 [2] 63 d3 [2] 7f fc }

  condition:
    any of them
}