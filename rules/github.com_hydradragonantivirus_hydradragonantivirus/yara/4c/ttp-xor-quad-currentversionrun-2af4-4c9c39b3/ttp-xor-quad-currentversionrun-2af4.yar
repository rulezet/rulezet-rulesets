rule TTP_XOR_QUAD_CurrentVersionRun_2af4 {
  strings:
    $key_2af4 = { 79 9b [2] 5d 95 [2] 76 b9 [2] 58 9b [2] 4c 80 [2] 43 9a [2] 5d 87 [2] 5f 86 [2] 44 80 [2] 58 87 [2] 44 a8 }

  condition:
    any of them
}