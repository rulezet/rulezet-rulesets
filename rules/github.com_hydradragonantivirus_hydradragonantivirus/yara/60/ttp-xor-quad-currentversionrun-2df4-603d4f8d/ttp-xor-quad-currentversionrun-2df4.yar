rule TTP_XOR_QUAD_CurrentVersionRun_2df4 {
  strings:
    $key_2df4 = { 7e 9b [2] 5a 95 [2] 71 b9 [2] 5f 9b [2] 4b 80 [2] 44 9a [2] 5a 87 [2] 58 86 [2] 43 80 [2] 5f 87 [2] 43 a8 }

  condition:
    any of them
}