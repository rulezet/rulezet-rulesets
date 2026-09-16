rule TTP_XOR_QUAD_CurrentVersionRun_4447 {
  strings:
    $key_4447 = { 17 28 [2] 33 26 [2] 18 0a [2] 36 28 [2] 22 33 [2] 2d 29 [2] 33 34 [2] 31 35 [2] 2a 33 [2] 36 34 [2] 2a 1b }

  condition:
    any of them
}