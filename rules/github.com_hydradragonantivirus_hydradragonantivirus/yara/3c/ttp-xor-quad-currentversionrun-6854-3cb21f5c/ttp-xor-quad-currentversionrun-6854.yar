rule TTP_XOR_QUAD_CurrentVersionRun_6854 {
  strings:
    $key_6854 = { 3b 3b [2] 1f 35 [2] 34 19 [2] 1a 3b [2] 0e 20 [2] 01 3a [2] 1f 27 [2] 1d 26 [2] 06 20 [2] 1a 27 [2] 06 08 }

  condition:
    any of them
}