rule TTP_XOR_QUAD_CurrentVersionRun_72a6 {
  strings:
    $key_72a6 = { 21 c9 [2] 05 c7 [2] 2e eb [2] 00 c9 [2] 14 d2 [2] 1b c8 [2] 05 d5 [2] 07 d4 [2] 1c d2 [2] 00 d5 [2] 1c fa }

  condition:
    any of them
}