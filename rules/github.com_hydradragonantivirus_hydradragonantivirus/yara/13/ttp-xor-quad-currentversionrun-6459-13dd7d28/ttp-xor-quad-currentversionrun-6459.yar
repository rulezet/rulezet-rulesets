rule TTP_XOR_QUAD_CurrentVersionRun_6459 {
  strings:
    $key_6459 = { 37 36 [2] 13 38 [2] 38 14 [2] 16 36 [2] 02 2d [2] 0d 37 [2] 13 2a [2] 11 2b [2] 0a 2d [2] 16 2a [2] 0a 05 }

  condition:
    any of them
}