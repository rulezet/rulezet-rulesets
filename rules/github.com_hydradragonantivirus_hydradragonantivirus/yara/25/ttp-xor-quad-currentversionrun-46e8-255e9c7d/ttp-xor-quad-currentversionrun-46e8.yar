rule TTP_XOR_QUAD_CurrentVersionRun_46e8 {
  strings:
    $key_46e8 = { 15 87 [2] 31 89 [2] 1a a5 [2] 34 87 [2] 20 9c [2] 2f 86 [2] 31 9b [2] 33 9a [2] 28 9c [2] 34 9b [2] 28 b4 }

  condition:
    any of them
}