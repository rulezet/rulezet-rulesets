rule TTP_XOR_QUAD_CurrentVersionRun_7bf4 {
  strings:
    $key_7bf4 = { 28 9b [2] 0c 95 [2] 27 b9 [2] 09 9b [2] 1d 80 [2] 12 9a [2] 0c 87 [2] 0e 86 [2] 15 80 [2] 09 87 [2] 15 a8 }

  condition:
    any of them
}