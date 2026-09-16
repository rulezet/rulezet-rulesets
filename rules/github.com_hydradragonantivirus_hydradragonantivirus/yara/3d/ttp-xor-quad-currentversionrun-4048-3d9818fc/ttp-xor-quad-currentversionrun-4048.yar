rule TTP_XOR_QUAD_CurrentVersionRun_4048 {
  strings:
    $key_4048 = { 13 27 [2] 37 29 [2] 1c 05 [2] 32 27 [2] 26 3c [2] 29 26 [2] 37 3b [2] 35 3a [2] 2e 3c [2] 32 3b [2] 2e 14 }

  condition:
    any of them
}