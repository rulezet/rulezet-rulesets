rule TTP_XOR_QUAD_CurrentVersionRun_7279 {
  strings:
    $key_7279 = { 21 16 [2] 05 18 [2] 2e 34 [2] 00 16 [2] 14 0d [2] 1b 17 [2] 05 0a [2] 07 0b [2] 1c 0d [2] 00 0a [2] 1c 25 }

  condition:
    any of them
}