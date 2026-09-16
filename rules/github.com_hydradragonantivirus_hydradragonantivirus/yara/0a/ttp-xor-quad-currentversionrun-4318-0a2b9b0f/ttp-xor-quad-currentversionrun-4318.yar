rule TTP_XOR_QUAD_CurrentVersionRun_4318 {
  strings:
    $key_4318 = { 10 77 [2] 34 79 [2] 1f 55 [2] 31 77 [2] 25 6c [2] 2a 76 [2] 34 6b [2] 36 6a [2] 2d 6c [2] 31 6b [2] 2d 44 }

  condition:
    any of them
}