rule TTP_XOR_QUAD_CurrentVersionRun_4764 {
  strings:
    $key_4764 = { 14 0b [2] 30 05 [2] 1b 29 [2] 35 0b [2] 21 10 [2] 2e 0a [2] 30 17 [2] 32 16 [2] 29 10 [2] 35 17 [2] 29 38 }

  condition:
    any of them
}