rule TTP_XOR_QUAD_CurrentVersionRun_2274 {
  strings:
    $key_2274 = { 71 1b [2] 55 15 [2] 7e 39 [2] 50 1b [2] 44 00 [2] 4b 1a [2] 55 07 [2] 57 06 [2] 4c 00 [2] 50 07 [2] 4c 28 }

  condition:
    any of them
}