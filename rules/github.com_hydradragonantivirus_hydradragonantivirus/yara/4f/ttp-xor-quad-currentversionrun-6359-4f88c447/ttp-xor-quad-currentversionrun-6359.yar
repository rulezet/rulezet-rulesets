rule TTP_XOR_QUAD_CurrentVersionRun_6359 {
  strings:
    $key_6359 = { 30 36 [2] 14 38 [2] 3f 14 [2] 11 36 [2] 05 2d [2] 0a 37 [2] 14 2a [2] 16 2b [2] 0d 2d [2] 11 2a [2] 0d 05 }

  condition:
    any of them
}