rule TTP_XOR_QUAD_CurrentVersionRun_4769 {
  strings:
    $key_4769 = { 14 06 [2] 30 08 [2] 1b 24 [2] 35 06 [2] 21 1d [2] 2e 07 [2] 30 1a [2] 32 1b [2] 29 1d [2] 35 1a [2] 29 35 }

  condition:
    any of them
}