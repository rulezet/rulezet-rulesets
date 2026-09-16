rule TTP_XOR_QUAD_CurrentVersionRun_6f48 {
  strings:
    $key_6f48 = { 3c 27 [2] 18 29 [2] 33 05 [2] 1d 27 [2] 09 3c [2] 06 26 [2] 18 3b [2] 1a 3a [2] 01 3c [2] 1d 3b [2] 01 14 }

  condition:
    any of them
}