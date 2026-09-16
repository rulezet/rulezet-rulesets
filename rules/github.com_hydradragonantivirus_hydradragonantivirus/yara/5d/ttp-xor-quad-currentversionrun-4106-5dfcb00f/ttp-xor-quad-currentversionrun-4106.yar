rule TTP_XOR_QUAD_CurrentVersionRun_4106 {
  strings:
    $key_4106 = { 12 69 [2] 36 67 [2] 1d 4b [2] 33 69 [2] 27 72 [2] 28 68 [2] 36 75 [2] 34 74 [2] 2f 72 [2] 33 75 [2] 2f 5a }

  condition:
    any of them
}