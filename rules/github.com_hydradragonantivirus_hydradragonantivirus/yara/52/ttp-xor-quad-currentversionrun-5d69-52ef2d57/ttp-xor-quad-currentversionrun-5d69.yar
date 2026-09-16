rule TTP_XOR_QUAD_CurrentVersionRun_5d69 {
  strings:
    $key_5d69 = { 0e 06 [2] 2a 08 [2] 01 24 [2] 2f 06 [2] 3b 1d [2] 34 07 [2] 2a 1a [2] 28 1b [2] 33 1d [2] 2f 1a [2] 33 35 }

  condition:
    any of them
}