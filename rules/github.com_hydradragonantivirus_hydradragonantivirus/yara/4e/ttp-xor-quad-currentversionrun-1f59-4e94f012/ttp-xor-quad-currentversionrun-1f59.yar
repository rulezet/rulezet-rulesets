rule TTP_XOR_QUAD_CurrentVersionRun_1f59 {
  strings:
    $key_1f59 = { 4c 36 [2] 68 38 [2] 43 14 [2] 6d 36 [2] 79 2d [2] 76 37 [2] 68 2a [2] 6a 2b [2] 71 2d [2] 6d 2a [2] 71 05 }

  condition:
    any of them
}