rule TTP_XOR_QUAD_CurrentVersionRun_4674 {
  strings:
    $key_4674 = { 15 1b [2] 31 15 [2] 1a 39 [2] 34 1b [2] 20 00 [2] 2f 1a [2] 31 07 [2] 33 06 [2] 28 00 [2] 34 07 [2] 28 28 }

  condition:
    any of them
}