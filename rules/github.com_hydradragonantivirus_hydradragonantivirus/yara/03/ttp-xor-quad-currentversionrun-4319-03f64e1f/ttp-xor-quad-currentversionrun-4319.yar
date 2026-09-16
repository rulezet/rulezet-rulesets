rule TTP_XOR_QUAD_CurrentVersionRun_4319 {
  strings:
    $key_4319 = { 10 76 [2] 34 78 [2] 1f 54 [2] 31 76 [2] 25 6d [2] 2a 77 [2] 34 6a [2] 36 6b [2] 2d 6d [2] 31 6a [2] 2d 45 }

  condition:
    any of them
}