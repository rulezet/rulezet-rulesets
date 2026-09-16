rule TTP_XOR_QUAD_CurrentVersionRun_4365 {
  strings:
    $key_4365 = { 10 0a [2] 34 04 [2] 1f 28 [2] 31 0a [2] 25 11 [2] 2a 0b [2] 34 16 [2] 36 17 [2] 2d 11 [2] 31 16 [2] 2d 39 }

  condition:
    any of them
}