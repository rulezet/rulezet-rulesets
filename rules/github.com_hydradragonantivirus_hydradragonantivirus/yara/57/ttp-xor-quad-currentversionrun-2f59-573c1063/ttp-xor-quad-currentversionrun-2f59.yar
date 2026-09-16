rule TTP_XOR_QUAD_CurrentVersionRun_2f59 {
  strings:
    $key_2f59 = { 7c 36 [2] 58 38 [2] 73 14 [2] 5d 36 [2] 49 2d [2] 46 37 [2] 58 2a [2] 5a 2b [2] 41 2d [2] 5d 2a [2] 41 05 }

  condition:
    any of them
}