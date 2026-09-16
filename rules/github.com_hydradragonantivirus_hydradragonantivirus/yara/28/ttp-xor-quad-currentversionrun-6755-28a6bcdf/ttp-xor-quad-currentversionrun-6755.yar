rule TTP_XOR_QUAD_CurrentVersionRun_6755 {
  strings:
    $key_6755 = { 34 3a [2] 10 34 [2] 3b 18 [2] 15 3a [2] 01 21 [2] 0e 3b [2] 10 26 [2] 12 27 [2] 09 21 [2] 15 26 [2] 09 09 }

  condition:
    any of them
}