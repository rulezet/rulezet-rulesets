rule TTP_XOR_QUAD_CurrentVersionRun_4159 {
  strings:
    $key_4159 = { 12 36 [2] 36 38 [2] 1d 14 [2] 33 36 [2] 27 2d [2] 28 37 [2] 36 2a [2] 34 2b [2] 2f 2d [2] 33 2a [2] 2f 05 }

  condition:
    any of them
}