rule TTP_XOR_QUAD_CurrentVersionRun_28e8 {
  strings:
    $key_28e8 = { 7b 87 [2] 5f 89 [2] 74 a5 [2] 5a 87 [2] 4e 9c [2] 41 86 [2] 5f 9b [2] 5d 9a [2] 46 9c [2] 5a 9b [2] 46 b4 }

  condition:
    any of them
}