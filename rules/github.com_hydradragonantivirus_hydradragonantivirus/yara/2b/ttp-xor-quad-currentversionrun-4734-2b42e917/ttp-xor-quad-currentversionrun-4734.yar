rule TTP_XOR_QUAD_CurrentVersionRun_4734 {
  strings:
    $key_4734 = { 14 5b [2] 30 55 [2] 1b 79 [2] 35 5b [2] 21 40 [2] 2e 5a [2] 30 47 [2] 32 46 [2] 29 40 [2] 35 47 [2] 29 68 }

  condition:
    any of them
}