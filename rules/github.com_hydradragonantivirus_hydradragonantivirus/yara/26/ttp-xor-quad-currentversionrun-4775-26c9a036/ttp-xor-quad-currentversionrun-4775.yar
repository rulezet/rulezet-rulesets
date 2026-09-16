rule TTP_XOR_QUAD_CurrentVersionRun_4775 {
  strings:
    $key_4775 = { 14 1a [2] 30 14 [2] 1b 38 [2] 35 1a [2] 21 01 [2] 2e 1b [2] 30 06 [2] 32 07 [2] 29 01 [2] 35 06 [2] 29 29 }

  condition:
    any of them
}