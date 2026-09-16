rule TTP_XOR_QUAD_CurrentVersionRun_5f59 {
  strings:
    $key_5f59 = { 0c 36 [2] 28 38 [2] 03 14 [2] 2d 36 [2] 39 2d [2] 36 37 [2] 28 2a [2] 2a 2b [2] 31 2d [2] 2d 2a [2] 31 05 }

  condition:
    any of them
}