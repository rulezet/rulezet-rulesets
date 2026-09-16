rule TTP_XOR_QUAD_CurrentVersionRun_ea77 {
  strings:
    $key_ea77 = { b9 18 [2] 9d 16 [2] b6 3a [2] 98 18 [2] 8c 03 [2] 83 19 [2] 9d 04 [2] 9f 05 [2] 84 03 [2] 98 04 [2] 84 2b }

  condition:
    any of them
}