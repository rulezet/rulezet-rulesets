rule TTP_XOR_QUAD_CurrentVersionRun_7272 {
  strings:
    $key_7272 = { 21 1d [2] 05 13 [2] 2e 3f [2] 00 1d [2] 14 06 [2] 1b 1c [2] 05 01 [2] 07 00 [2] 1c 06 [2] 00 01 [2] 1c 2e }

  condition:
    any of them
}