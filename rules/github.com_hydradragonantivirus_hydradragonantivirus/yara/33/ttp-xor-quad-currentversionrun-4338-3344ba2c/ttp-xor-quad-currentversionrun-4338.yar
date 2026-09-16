rule TTP_XOR_QUAD_CurrentVersionRun_4338 {
  strings:
    $key_4338 = { 10 57 [2] 34 59 [2] 1f 75 [2] 31 57 [2] 25 4c [2] 2a 56 [2] 34 4b [2] 36 4a [2] 2d 4c [2] 31 4b [2] 2d 64 }

  condition:
    any of them
}