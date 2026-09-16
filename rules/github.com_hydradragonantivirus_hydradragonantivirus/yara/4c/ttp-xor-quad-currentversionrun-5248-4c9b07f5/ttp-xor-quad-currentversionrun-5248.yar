rule TTP_XOR_QUAD_CurrentVersionRun_5248 {
  strings:
    $key_5248 = { 01 27 [2] 25 29 [2] 0e 05 [2] 20 27 [2] 34 3c [2] 3b 26 [2] 25 3b [2] 27 3a [2] 3c 3c [2] 20 3b [2] 3c 14 }

  condition:
    any of them
}