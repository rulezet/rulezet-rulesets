rule TTP_XOR_QUAD_CurrentVersionRun_47e8 {
  strings:
    $key_47e8 = { 14 87 [2] 30 89 [2] 1b a5 [2] 35 87 [2] 21 9c [2] 2e 86 [2] 30 9b [2] 32 9a [2] 29 9c [2] 35 9b [2] 29 b4 }

  condition:
    any of them
}