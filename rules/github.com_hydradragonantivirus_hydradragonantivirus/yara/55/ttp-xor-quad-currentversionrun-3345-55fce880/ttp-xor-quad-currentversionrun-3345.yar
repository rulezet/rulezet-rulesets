rule TTP_XOR_QUAD_CurrentVersionRun_3345 {
  strings:
    $key_3345 = { 60 2a [2] 44 24 [2] 6f 08 [2] 41 2a [2] 55 31 [2] 5a 2b [2] 44 36 [2] 46 37 [2] 5d 31 [2] 41 36 [2] 5d 19 }

  condition:
    any of them
}