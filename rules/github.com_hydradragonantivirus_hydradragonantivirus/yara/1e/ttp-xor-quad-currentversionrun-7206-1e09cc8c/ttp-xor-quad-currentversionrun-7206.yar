rule TTP_XOR_QUAD_CurrentVersionRun_7206 {
  strings:
    $key_7206 = { 21 69 [2] 05 67 [2] 2e 4b [2] 00 69 [2] 14 72 [2] 1b 68 [2] 05 75 [2] 07 74 [2] 1c 72 [2] 00 75 [2] 1c 5a }

  condition:
    any of them
}