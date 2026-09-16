rule TTP_XOR_QUAD_CurrentVersionRun_6855 {
  strings:
    $key_6855 = { 3b 3a [2] 1f 34 [2] 34 18 [2] 1a 3a [2] 0e 21 [2] 01 3b [2] 1f 26 [2] 1d 27 [2] 06 21 [2] 1a 26 [2] 06 09 }

  condition:
    any of them
}