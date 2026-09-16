rule TTP_XOR_QUAD_CurrentVersionRun_10f5 {
  strings:
    $key_10f5 = { 43 9a [2] 67 94 [2] 4c b8 [2] 62 9a [2] 76 81 [2] 79 9b [2] 67 86 [2] 65 87 [2] 7e 81 [2] 62 86 [2] 7e a9 }

  condition:
    any of them
}