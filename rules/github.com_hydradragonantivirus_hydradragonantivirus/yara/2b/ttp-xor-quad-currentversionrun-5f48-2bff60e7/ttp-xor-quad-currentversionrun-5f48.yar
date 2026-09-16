rule TTP_XOR_QUAD_CurrentVersionRun_5f48 {
  strings:
    $key_5f48 = { 0c 27 [2] 28 29 [2] 03 05 [2] 2d 27 [2] 39 3c [2] 36 26 [2] 28 3b [2] 2a 3a [2] 31 3c [2] 2d 3b [2] 31 14 }

  condition:
    any of them
}