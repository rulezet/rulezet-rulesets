rule TTP_XOR_QUAD_CurrentVersionRun_7275 {
  strings:
    $key_7275 = { 21 1a [2] 05 14 [2] 2e 38 [2] 00 1a [2] 14 01 [2] 1b 1b [2] 05 06 [2] 07 07 [2] 1c 01 [2] 00 06 [2] 1c 29 }

  condition:
    any of them
}