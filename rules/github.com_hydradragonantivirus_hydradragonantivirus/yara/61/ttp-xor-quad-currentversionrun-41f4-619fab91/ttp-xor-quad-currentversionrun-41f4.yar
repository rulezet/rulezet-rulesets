rule TTP_XOR_QUAD_CurrentVersionRun_41f4 {
  strings:
    $key_41f4 = { 12 9b [2] 36 95 [2] 1d b9 [2] 33 9b [2] 27 80 [2] 28 9a [2] 36 87 [2] 34 86 [2] 2f 80 [2] 33 87 [2] 2f a8 }

  condition:
    any of them
}