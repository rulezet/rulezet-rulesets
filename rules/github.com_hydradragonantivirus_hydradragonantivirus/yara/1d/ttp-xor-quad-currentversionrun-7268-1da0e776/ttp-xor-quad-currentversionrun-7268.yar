rule TTP_XOR_QUAD_CurrentVersionRun_7268 {
  strings:
    $key_7268 = { 21 07 [2] 05 09 [2] 2e 25 [2] 00 07 [2] 14 1c [2] 1b 06 [2] 05 1b [2] 07 1a [2] 1c 1c [2] 00 1b [2] 1c 34 }

  condition:
    any of them
}