rule TTP_XOR_QUAD_CurrentVersionRun_7244 {
  strings:
    $key_7244 = { 21 2b [2] 05 25 [2] 2e 09 [2] 00 2b [2] 14 30 [2] 1b 2a [2] 05 37 [2] 07 36 [2] 1c 30 [2] 00 37 [2] 1c 18 }

  condition:
    any of them
}