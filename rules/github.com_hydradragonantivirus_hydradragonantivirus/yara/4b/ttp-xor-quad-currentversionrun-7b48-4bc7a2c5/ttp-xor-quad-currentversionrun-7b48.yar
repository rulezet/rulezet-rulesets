rule TTP_XOR_QUAD_CurrentVersionRun_7b48 {
  strings:
    $key_7b48 = { 28 27 [2] 0c 29 [2] 27 05 [2] 09 27 [2] 1d 3c [2] 12 26 [2] 0c 3b [2] 0e 3a [2] 15 3c [2] 09 3b [2] 15 14 }

  condition:
    any of them
}