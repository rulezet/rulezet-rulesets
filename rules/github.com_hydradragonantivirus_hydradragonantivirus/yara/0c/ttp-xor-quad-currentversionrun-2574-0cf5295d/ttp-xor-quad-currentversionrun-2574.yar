rule TTP_XOR_QUAD_CurrentVersionRun_2574 {
  strings:
    $key_2574 = { 76 1b [2] 52 15 [2] 79 39 [2] 57 1b [2] 43 00 [2] 4c 1a [2] 52 07 [2] 50 06 [2] 4b 00 [2] 57 07 [2] 4b 28 }

  condition:
    any of them
}