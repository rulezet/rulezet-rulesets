rule TTP_XOR_QUAD_CurrentVersionRun_5a59 {
  strings:
    $key_5a59 = { 09 36 [2] 2d 38 [2] 06 14 [2] 28 36 [2] 3c 2d [2] 33 37 [2] 2d 2a [2] 2f 2b [2] 34 2d [2] 28 2a [2] 34 05 }

  condition:
    any of them
}