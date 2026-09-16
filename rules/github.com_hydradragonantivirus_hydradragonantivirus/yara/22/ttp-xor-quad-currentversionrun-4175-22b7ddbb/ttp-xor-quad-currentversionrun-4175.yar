rule TTP_XOR_QUAD_CurrentVersionRun_4175 {
  strings:
    $key_4175 = { 12 1a [2] 36 14 [2] 1d 38 [2] 33 1a [2] 27 01 [2] 28 1b [2] 36 06 [2] 34 07 [2] 2f 01 [2] 33 06 [2] 2f 29 }

  condition:
    any of them
}