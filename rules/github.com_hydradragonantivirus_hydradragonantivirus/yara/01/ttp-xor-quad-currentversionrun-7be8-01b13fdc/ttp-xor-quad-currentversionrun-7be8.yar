rule TTP_XOR_QUAD_CurrentVersionRun_7be8 {
  strings:
    $key_7be8 = { 28 87 [2] 0c 89 [2] 27 a5 [2] 09 87 [2] 1d 9c [2] 12 86 [2] 0c 9b [2] 0e 9a [2] 15 9c [2] 09 9b [2] 15 b4 }

  condition:
    any of them
}