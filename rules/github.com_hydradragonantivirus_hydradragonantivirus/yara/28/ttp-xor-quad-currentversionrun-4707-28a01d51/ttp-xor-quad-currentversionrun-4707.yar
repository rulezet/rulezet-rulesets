rule TTP_XOR_QUAD_CurrentVersionRun_4707 {
  strings:
    $key_4707 = { 14 68 [2] 30 66 [2] 1b 4a [2] 35 68 [2] 21 73 [2] 2e 69 [2] 30 74 [2] 32 75 [2] 29 73 [2] 35 74 [2] 29 5b }

  condition:
    any of them
}