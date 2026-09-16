rule TTP_XOR_QUAD_CurrentVersionRun_4356 {
  strings:
    $key_4356 = { 10 39 [2] 34 37 [2] 1f 1b [2] 31 39 [2] 25 22 [2] 2a 38 [2] 34 25 [2] 36 24 [2] 2d 22 [2] 31 25 [2] 2d 0a }

  condition:
    any of them
}