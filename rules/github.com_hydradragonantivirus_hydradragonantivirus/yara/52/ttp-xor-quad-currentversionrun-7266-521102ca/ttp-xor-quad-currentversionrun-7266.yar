rule TTP_XOR_QUAD_CurrentVersionRun_7266 {
  strings:
    $key_7266 = { 21 09 [2] 05 07 [2] 2e 2b [2] 00 09 [2] 14 12 [2] 1b 08 [2] 05 15 [2] 07 14 [2] 1c 12 [2] 00 15 [2] 1c 3a }

  condition:
    any of them
}