rule TTP_XOR_QUAD_CurrentVersionRun_5668 {
  strings:
    $key_5668 = { 05 07 [2] 21 09 [2] 0a 25 [2] 24 07 [2] 30 1c [2] 3f 06 [2] 21 1b [2] 23 1a [2] 38 1c [2] 24 1b [2] 38 34 }

  condition:
    any of them
}