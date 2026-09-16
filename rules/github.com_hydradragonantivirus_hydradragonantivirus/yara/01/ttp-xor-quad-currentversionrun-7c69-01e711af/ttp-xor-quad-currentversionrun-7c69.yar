rule TTP_XOR_QUAD_CurrentVersionRun_7c69 {
  strings:
    $key_7c69 = { 2f 06 [2] 0b 08 [2] 20 24 [2] 0e 06 [2] 1a 1d [2] 15 07 [2] 0b 1a [2] 09 1b [2] 12 1d [2] 0e 1a [2] 12 35 }

  condition:
    any of them
}