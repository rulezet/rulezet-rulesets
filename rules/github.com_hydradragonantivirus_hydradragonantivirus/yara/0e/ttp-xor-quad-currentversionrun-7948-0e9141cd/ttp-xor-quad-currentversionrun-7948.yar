rule TTP_XOR_QUAD_CurrentVersionRun_7948 {
  strings:
    $key_7948 = { 2a 27 [2] 0e 29 [2] 25 05 [2] 0b 27 [2] 1f 3c [2] 10 26 [2] 0e 3b [2] 0c 3a [2] 17 3c [2] 0b 3b [2] 17 14 }

  condition:
    any of them
}