rule TTP_XOR_QUAD_CurrentVersionRun_4136 {
  strings:
    $key_4136 = { 12 59 [2] 36 57 [2] 1d 7b [2] 33 59 [2] 27 42 [2] 28 58 [2] 36 45 [2] 34 44 [2] 2f 42 [2] 33 45 [2] 2f 6a }

  condition:
    any of them
}