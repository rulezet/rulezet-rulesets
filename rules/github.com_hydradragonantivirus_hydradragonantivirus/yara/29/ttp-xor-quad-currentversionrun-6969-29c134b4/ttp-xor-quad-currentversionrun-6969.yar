rule TTP_XOR_QUAD_CurrentVersionRun_6969 {
  strings:
    $key_6969 = { 3a 06 [2] 1e 08 [2] 35 24 [2] 1b 06 [2] 0f 1d [2] 00 07 [2] 1e 1a [2] 1c 1b [2] 07 1d [2] 1b 1a [2] 07 35 }

  condition:
    any of them
}