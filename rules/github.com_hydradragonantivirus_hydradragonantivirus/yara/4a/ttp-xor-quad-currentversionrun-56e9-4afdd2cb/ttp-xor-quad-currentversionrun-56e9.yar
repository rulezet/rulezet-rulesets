rule TTP_XOR_QUAD_CurrentVersionRun_56e9 {
  strings:
    $key_56e9 = { 05 86 [2] 21 88 [2] 0a a4 [2] 24 86 [2] 30 9d [2] 3f 87 [2] 21 9a [2] 23 9b [2] 38 9d [2] 24 9a [2] 38 b5 }

  condition:
    any of them
}