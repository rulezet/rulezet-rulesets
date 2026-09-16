rule TTP_XOR_QUAD_CurrentVersionRun_6668 {
  strings:
    $key_6668 = { 35 07 [2] 11 09 [2] 3a 25 [2] 14 07 [2] 00 1c [2] 0f 06 [2] 11 1b [2] 13 1a [2] 08 1c [2] 14 1b [2] 08 34 }

  condition:
    any of them
}