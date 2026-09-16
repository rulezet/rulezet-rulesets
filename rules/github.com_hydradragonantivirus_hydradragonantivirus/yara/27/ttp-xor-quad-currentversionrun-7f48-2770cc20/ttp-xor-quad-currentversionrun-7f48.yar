rule TTP_XOR_QUAD_CurrentVersionRun_7f48 {
  strings:
    $key_7f48 = { 2c 27 [2] 08 29 [2] 23 05 [2] 0d 27 [2] 19 3c [2] 16 26 [2] 08 3b [2] 0a 3a [2] 11 3c [2] 0d 3b [2] 11 14 }

  condition:
    any of them
}