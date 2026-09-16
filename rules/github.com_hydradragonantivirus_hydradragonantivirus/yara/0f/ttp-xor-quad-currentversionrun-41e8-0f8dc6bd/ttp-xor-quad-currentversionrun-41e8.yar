rule TTP_XOR_QUAD_CurrentVersionRun_41e8 {
  strings:
    $key_41e8 = { 12 87 [2] 36 89 [2] 1d a5 [2] 33 87 [2] 27 9c [2] 28 86 [2] 36 9b [2] 34 9a [2] 2f 9c [2] 33 9b [2] 2f b4 }

  condition:
    any of them
}