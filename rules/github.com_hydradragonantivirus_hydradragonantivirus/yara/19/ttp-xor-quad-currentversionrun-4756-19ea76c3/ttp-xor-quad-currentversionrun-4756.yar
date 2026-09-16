rule TTP_XOR_QUAD_CurrentVersionRun_4756 {
  strings:
    $key_4756 = { 14 39 [2] 30 37 [2] 1b 1b [2] 35 39 [2] 21 22 [2] 2e 38 [2] 30 25 [2] 32 24 [2] 29 22 [2] 35 25 [2] 29 0a }

  condition:
    any of them
}