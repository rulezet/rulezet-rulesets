rule TTP_XOR_QUAD_CurrentVersionRun_4305 {
  strings:
    $key_4305 = { 10 6a [2] 34 64 [2] 1f 48 [2] 31 6a [2] 25 71 [2] 2a 6b [2] 34 76 [2] 36 77 [2] 2d 71 [2] 31 76 [2] 2d 59 }

  condition:
    any of them
}