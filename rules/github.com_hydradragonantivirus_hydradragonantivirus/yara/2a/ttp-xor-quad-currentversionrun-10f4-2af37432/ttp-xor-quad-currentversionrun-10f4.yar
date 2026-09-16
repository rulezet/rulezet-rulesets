rule TTP_XOR_QUAD_CurrentVersionRun_10f4 {
  strings:
    $key_10f4 = { 43 9b [2] 67 95 [2] 4c b9 [2] 62 9b [2] 76 80 [2] 79 9a [2] 67 87 [2] 65 86 [2] 7e 80 [2] 62 87 [2] 7e a8 }

  condition:
    any of them
}