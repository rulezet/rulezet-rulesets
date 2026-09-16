rule TTP_XOR_QUAD_CurrentVersionRun_1574 {
  strings:
    $key_1574 = { 46 1b [2] 62 15 [2] 49 39 [2] 67 1b [2] 73 00 [2] 7c 1a [2] 62 07 [2] 60 06 [2] 7b 00 [2] 67 07 [2] 7b 28 }

  condition:
    any of them
}