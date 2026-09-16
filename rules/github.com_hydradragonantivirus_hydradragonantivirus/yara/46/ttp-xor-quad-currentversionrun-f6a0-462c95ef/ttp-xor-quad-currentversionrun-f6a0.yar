rule TTP_XOR_QUAD_CurrentVersionRun_f6a0 {
  strings:
    $key_f6a0 = { a5 cf [2] 81 c1 [2] aa ed [2] 84 cf [2] 90 d4 [2] 9f ce [2] 81 d3 [2] 83 d2 [2] 98 d4 [2] 84 d3 [2] 98 fc }

  condition:
    any of them
}