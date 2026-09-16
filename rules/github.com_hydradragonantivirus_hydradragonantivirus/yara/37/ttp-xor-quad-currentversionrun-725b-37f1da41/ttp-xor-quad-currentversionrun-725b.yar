rule TTP_XOR_QUAD_CurrentVersionRun_725b {
  strings:
    $key_725b = { 21 34 [2] 05 3a [2] 2e 16 [2] 00 34 [2] 14 2f [2] 1b 35 [2] 05 28 [2] 07 29 [2] 1c 2f [2] 00 28 [2] 1c 07 }

  condition:
    any of them
}