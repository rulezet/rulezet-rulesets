rule TTP_XOR_QUAD_CurrentVersionRun_28f4 {
  strings:
    $key_28f4 = { 7b 9b [2] 5f 95 [2] 74 b9 [2] 5a 9b [2] 4e 80 [2] 41 9a [2] 5f 87 [2] 5d 86 [2] 46 80 [2] 5a 87 [2] 46 a8 }

  condition:
    any of them
}