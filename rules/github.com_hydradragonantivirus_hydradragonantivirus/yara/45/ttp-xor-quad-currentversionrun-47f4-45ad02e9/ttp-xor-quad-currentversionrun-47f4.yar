rule TTP_XOR_QUAD_CurrentVersionRun_47f4 {
  strings:
    $key_47f4 = { 14 9b [2] 30 95 [2] 1b b9 [2] 35 9b [2] 21 80 [2] 2e 9a [2] 30 87 [2] 32 86 [2] 29 80 [2] 35 87 [2] 29 a8 }

  condition:
    any of them
}