rule TTP_XOR_QUAD_CurrentVersionRun_432b {
  strings:
    $key_432b = { 10 44 [2] 34 4a [2] 1f 66 [2] 31 44 [2] 25 5f [2] 2a 45 [2] 34 58 [2] 36 59 [2] 2d 5f [2] 31 58 [2] 2d 77 }

  condition:
    any of them
}