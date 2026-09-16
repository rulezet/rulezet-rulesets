rule TTP_XOR_QUAD_CurrentVersionRun_0848 {
  strings:
    $key_0848 = { 5b 27 [2] 7f 29 [2] 54 05 [2] 7a 27 [2] 6e 3c [2] 61 26 [2] 7f 3b [2] 7d 3a [2] 66 3c [2] 7a 3b [2] 66 14 }

  condition:
    any of them
}