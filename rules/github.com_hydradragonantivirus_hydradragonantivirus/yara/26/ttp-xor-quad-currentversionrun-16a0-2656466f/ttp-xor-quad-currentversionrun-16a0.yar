rule TTP_XOR_QUAD_CurrentVersionRun_16a0 {
  strings:
    $key_16a0 = { 45 cf [2] 61 c1 [2] 4a ed [2] 64 cf [2] 70 d4 [2] 7f ce [2] 61 d3 [2] 63 d2 [2] 78 d4 [2] 64 d3 [2] 78 fc }

  condition:
    any of them
}