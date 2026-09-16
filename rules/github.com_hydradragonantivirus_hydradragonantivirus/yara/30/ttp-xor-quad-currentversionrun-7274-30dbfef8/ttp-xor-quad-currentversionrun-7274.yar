rule TTP_XOR_QUAD_CurrentVersionRun_7274 {
  strings:
    $key_7274 = { 21 1b [2] 05 15 [2] 2e 39 [2] 00 1b [2] 14 00 [2] 1b 1a [2] 05 07 [2] 07 06 [2] 1c 00 [2] 00 07 [2] 1c 28 }

  condition:
    any of them
}