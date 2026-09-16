rule TTP_XOR_QUAD_CurrentVersionRun_6f59 {
  strings:
    $key_6f59 = { 3c 36 [2] 18 38 [2] 33 14 [2] 1d 36 [2] 09 2d [2] 06 37 [2] 18 2a [2] 1a 2b [2] 01 2d [2] 1d 2a [2] 01 05 }

  condition:
    any of them
}