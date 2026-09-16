rule TTP_XOR_QUAD_CurrentVersionRun_33f4 {
  strings:
    $key_33f4 = { 60 9b [2] 44 95 [2] 6f b9 [2] 41 9b [2] 55 80 [2] 5a 9a [2] 44 87 [2] 46 86 [2] 5d 80 [2] 41 87 [2] 5d a8 }

  condition:
    any of them
}