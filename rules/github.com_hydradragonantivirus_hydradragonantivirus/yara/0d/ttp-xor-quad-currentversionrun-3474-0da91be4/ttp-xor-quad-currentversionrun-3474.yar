rule TTP_XOR_QUAD_CurrentVersionRun_3474 {
  strings:
    $key_3474 = { 67 1b [2] 43 15 [2] 68 39 [2] 46 1b [2] 52 00 [2] 5d 1a [2] 43 07 [2] 41 06 [2] 5a 00 [2] 46 07 [2] 5a 28 }

  condition:
    any of them
}