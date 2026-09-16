rule TTP_XOR_QUAD_CurrentVersionRun_4de8 {
  strings:
    $key_4de8 = { 1e 87 [2] 3a 89 [2] 11 a5 [2] 3f 87 [2] 2b 9c [2] 24 86 [2] 3a 9b [2] 38 9a [2] 23 9c [2] 3f 9b [2] 23 b4 }

  condition:
    any of them
}