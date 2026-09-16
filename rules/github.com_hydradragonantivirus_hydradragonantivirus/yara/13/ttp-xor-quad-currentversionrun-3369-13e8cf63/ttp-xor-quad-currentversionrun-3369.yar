rule TTP_XOR_QUAD_CurrentVersionRun_3369 {
  strings:
    $key_3369 = { 60 06 [2] 44 08 [2] 6f 24 [2] 41 06 [2] 55 1d [2] 5a 07 [2] 44 1a [2] 46 1b [2] 5d 1d [2] 41 1a [2] 5d 35 }

  condition:
    any of them
}