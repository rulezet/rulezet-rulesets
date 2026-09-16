rule TTP_XOR_QUAD_CurrentVersionRun_4306 {
  strings:
    $key_4306 = { 10 69 [2] 34 67 [2] 1f 4b [2] 31 69 [2] 25 72 [2] 2a 68 [2] 34 75 [2] 36 74 [2] 2d 72 [2] 31 75 [2] 2d 5a }

  condition:
    any of them
}