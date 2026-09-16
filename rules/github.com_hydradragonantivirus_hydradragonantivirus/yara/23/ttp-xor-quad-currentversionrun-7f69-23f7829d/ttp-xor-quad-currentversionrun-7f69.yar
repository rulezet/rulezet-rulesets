rule TTP_XOR_QUAD_CurrentVersionRun_7f69 {
  strings:
    $key_7f69 = { 2c 06 [2] 08 08 [2] 23 24 [2] 0d 06 [2] 19 1d [2] 16 07 [2] 08 1a [2] 0a 1b [2] 11 1d [2] 0d 1a [2] 11 35 }

  condition:
    any of them
}