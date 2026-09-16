rule TTP_XOR_QUAD_CurrentVersionRun_f7a0 {
  strings:
    $key_f7a0 = { a4 cf [2] 80 c1 [2] ab ed [2] 85 cf [2] 91 d4 [2] 9e ce [2] 80 d3 [2] 82 d2 [2] 99 d4 [2] 85 d3 [2] 99 fc }

  condition:
    any of them
}