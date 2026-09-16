rule TTP_XOR_QUAD_CurrentVersionRun_4364 {
  strings:
    $key_4364 = { 10 0b [2] 34 05 [2] 1f 29 [2] 31 0b [2] 25 10 [2] 2a 0a [2] 34 17 [2] 36 16 [2] 2d 10 [2] 31 17 [2] 2d 38 }

  condition:
    any of them
}