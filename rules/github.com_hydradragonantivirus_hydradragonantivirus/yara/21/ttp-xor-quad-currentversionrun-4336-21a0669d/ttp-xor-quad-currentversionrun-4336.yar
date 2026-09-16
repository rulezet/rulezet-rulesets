rule TTP_XOR_QUAD_CurrentVersionRun_4336 {
  strings:
    $key_4336 = { 10 59 [2] 34 57 [2] 1f 7b [2] 31 59 [2] 25 42 [2] 2a 58 [2] 34 45 [2] 36 44 [2] 2d 42 [2] 31 45 [2] 2d 6a }

  condition:
    any of them
}