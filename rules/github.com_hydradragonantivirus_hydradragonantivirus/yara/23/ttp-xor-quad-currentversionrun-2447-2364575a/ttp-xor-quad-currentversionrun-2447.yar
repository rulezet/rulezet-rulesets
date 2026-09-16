rule TTP_XOR_QUAD_CurrentVersionRun_2447 {
  strings:
    $key_2447 = { 77 28 [2] 53 26 [2] 78 0a [2] 56 28 [2] 42 33 [2] 4d 29 [2] 53 34 [2] 51 35 [2] 4a 33 [2] 56 34 [2] 4a 1b }

  condition:
    any of them
}