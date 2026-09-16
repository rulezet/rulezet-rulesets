rule TTP_XOR_QUAD_CurrentVersionRun_0356 {
  strings:
    $key_0356 = { 50 39 [2] 74 37 [2] 5f 1b [2] 71 39 [2] 65 22 [2] 6a 38 [2] 74 25 [2] 76 24 [2] 6d 22 [2] 71 25 [2] 6d 0a }

  condition:
    any of them
}