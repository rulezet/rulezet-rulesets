rule TTP_XOR_QUAD_CurrentVersionRun_33f5 {
  strings:
    $key_33f5 = { 60 9a [2] 44 94 [2] 6f b8 [2] 41 9a [2] 55 81 [2] 5a 9b [2] 44 86 [2] 46 87 [2] 5d 81 [2] 41 86 [2] 5d a9 }

  condition:
    any of them
}