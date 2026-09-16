rule TTP_XOR_QUAD_CurrentVersionRun_3359 {
  strings:
    $key_3359 = { 60 36 [2] 44 38 [2] 6f 14 [2] 41 36 [2] 55 2d [2] 5a 37 [2] 44 2a [2] 46 2b [2] 5d 2d [2] 41 2a [2] 5d 05 }

  condition:
    any of them
}