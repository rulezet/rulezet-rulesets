rule TTP_XOR_QUAD_CurrentVersionRun_56e8 {
  strings:
    $key_56e8 = { 05 87 [2] 21 89 [2] 0a a5 [2] 24 87 [2] 30 9c [2] 3f 86 [2] 21 9b [2] 23 9a [2] 38 9c [2] 24 9b [2] 38 b4 }

  condition:
    any of them
}