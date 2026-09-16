rule TTP_XOR_QUAD_CurrentVersionRun_4767 {
  strings:
    $key_4767 = { 14 08 [2] 30 06 [2] 1b 2a [2] 35 08 [2] 21 13 [2] 2e 09 [2] 30 14 [2] 32 15 [2] 29 13 [2] 35 14 [2] 29 3b }

  condition:
    any of them
}