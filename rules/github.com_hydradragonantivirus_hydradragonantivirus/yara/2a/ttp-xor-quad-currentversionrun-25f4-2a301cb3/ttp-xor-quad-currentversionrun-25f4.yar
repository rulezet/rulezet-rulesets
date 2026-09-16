rule TTP_XOR_QUAD_CurrentVersionRun_25f4 {
  strings:
    $key_25f4 = { 76 9b [2] 52 95 [2] 79 b9 [2] 57 9b [2] 43 80 [2] 4c 9a [2] 52 87 [2] 50 86 [2] 4b 80 [2] 57 87 [2] 4b a8 }

  condition:
    any of them
}