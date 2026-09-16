rule TTP_XOR_QUAD_CurrentVersionRun_7576 {
  strings:
    $key_7576 = { 26 19 [2] 02 17 [2] 29 3b [2] 07 19 [2] 13 02 [2] 1c 18 [2] 02 05 [2] 00 04 [2] 1b 02 [2] 07 05 [2] 1b 2a }

  condition:
    any of them
}