rule TTP_XOR_QUAD_CurrentVersionRun_771b {
  strings:
    $key_771b = { 24 74 [2] 00 7a [2] 2b 56 [2] 05 74 [2] 11 6f [2] 1e 75 [2] 00 68 [2] 02 69 [2] 19 6f [2] 05 68 [2] 19 47 }

  condition:
    any of them
}