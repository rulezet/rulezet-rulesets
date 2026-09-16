rule TTP_XOR_QUAD_CurrentVersionRun_5669 {
  strings:
    $key_5669 = { 05 06 [2] 21 08 [2] 0a 24 [2] 24 06 [2] 30 1d [2] 3f 07 [2] 21 1a [2] 23 1b [2] 38 1d [2] 24 1a [2] 38 35 }

  condition:
    any of them
}