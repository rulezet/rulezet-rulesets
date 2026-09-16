rule TTP_XOR_QUAD_CurrentVersionRun_4307 {
  strings:
    $key_4307 = { 10 68 [2] 34 66 [2] 1f 4a [2] 31 68 [2] 25 73 [2] 2a 69 [2] 34 74 [2] 36 75 [2] 2d 73 [2] 31 74 [2] 2d 5b }

  condition:
    any of them
}