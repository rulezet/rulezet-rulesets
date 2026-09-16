rule TTP_XOR_QUAD_CurrentVersionRun_4367 {
  strings:
    $key_4367 = { 10 08 [2] 34 06 [2] 1f 2a [2] 31 08 [2] 25 13 [2] 2a 09 [2] 34 14 [2] 36 15 [2] 2d 13 [2] 31 14 [2] 2d 3b }

  condition:
    any of them
}