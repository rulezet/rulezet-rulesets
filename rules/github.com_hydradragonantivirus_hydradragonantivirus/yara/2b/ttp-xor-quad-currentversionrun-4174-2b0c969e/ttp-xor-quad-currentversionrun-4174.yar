rule TTP_XOR_QUAD_CurrentVersionRun_4174 {
  strings:
    $key_4174 = { 12 1b [2] 36 15 [2] 1d 39 [2] 33 1b [2] 27 00 [2] 28 1a [2] 36 07 [2] 34 06 [2] 2f 00 [2] 33 07 [2] 2f 28 }

  condition:
    any of them
}