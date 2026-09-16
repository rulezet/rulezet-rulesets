rule TTP_XOR_QUAD_CurrentVersionRun_67e8 {
  strings:
    $key_67e8 = { 34 87 [2] 10 89 [2] 3b a5 [2] 15 87 [2] 01 9c [2] 0e 86 [2] 10 9b [2] 12 9a [2] 09 9c [2] 15 9b [2] 09 b4 }

  condition:
    any of them
}