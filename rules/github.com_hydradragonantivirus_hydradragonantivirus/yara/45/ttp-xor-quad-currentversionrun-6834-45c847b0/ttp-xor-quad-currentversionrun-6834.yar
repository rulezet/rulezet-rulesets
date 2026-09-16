rule TTP_XOR_QUAD_CurrentVersionRun_6834 {
  strings:
    $key_6834 = { 3b 5b [2] 1f 55 [2] 34 79 [2] 1a 5b [2] 0e 40 [2] 01 5a [2] 1f 47 [2] 1d 46 [2] 06 40 [2] 1a 47 [2] 06 68 }

  condition:
    any of them
}