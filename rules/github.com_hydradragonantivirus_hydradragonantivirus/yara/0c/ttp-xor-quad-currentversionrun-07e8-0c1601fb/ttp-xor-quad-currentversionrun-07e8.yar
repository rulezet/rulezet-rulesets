rule TTP_XOR_QUAD_CurrentVersionRun_07e8 {
  strings:
    $key_07e8 = { 54 87 [2] 70 89 [2] 5b a5 [2] 75 87 [2] 61 9c [2] 6e 86 [2] 70 9b [2] 72 9a [2] 69 9c [2] 75 9b [2] 69 b4 }

  condition:
    any of them
}