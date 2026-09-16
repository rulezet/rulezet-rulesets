rule TTP_XOR_QUAD_CurrentVersionRun_6669 {
  strings:
    $key_6669 = { 35 06 [2] 11 08 [2] 3a 24 [2] 14 06 [2] 00 1d [2] 0f 07 [2] 11 1a [2] 13 1b [2] 08 1d [2] 14 1a [2] 08 35 }

  condition:
    any of them
}