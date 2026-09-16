rule TTP_XOR_QUAD_CurrentVersionRun_4344 {
  strings:
    $key_4344 = { 10 2b [2] 34 25 [2] 1f 09 [2] 31 2b [2] 25 30 [2] 2a 2a [2] 34 37 [2] 36 36 [2] 2d 30 [2] 31 37 [2] 2d 18 }

  condition:
    any of them
}