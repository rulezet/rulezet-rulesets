rule TTP_XOR_QUAD_CurrentVersionRun_7215 {
  strings:
    $key_7215 = { 21 7a [2] 05 74 [2] 2e 58 [2] 00 7a [2] 14 61 [2] 1b 7b [2] 05 66 [2] 07 67 [2] 1c 61 [2] 00 66 [2] 1c 49 }

  condition:
    any of them
}