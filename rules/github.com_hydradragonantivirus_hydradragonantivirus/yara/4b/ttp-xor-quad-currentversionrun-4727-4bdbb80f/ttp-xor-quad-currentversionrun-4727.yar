rule TTP_XOR_QUAD_CurrentVersionRun_4727 {
  strings:
    $key_4727 = { 14 48 [2] 30 46 [2] 1b 6a [2] 35 48 [2] 21 53 [2] 2e 49 [2] 30 54 [2] 32 55 [2] 29 53 [2] 35 54 [2] 29 7b }

  condition:
    any of them
}