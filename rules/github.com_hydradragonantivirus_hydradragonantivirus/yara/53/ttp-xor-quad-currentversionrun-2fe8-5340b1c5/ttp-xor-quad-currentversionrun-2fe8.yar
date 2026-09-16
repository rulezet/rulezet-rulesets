rule TTP_XOR_QUAD_CurrentVersionRun_2fe8 {
  strings:
    $key_2fe8 = { 7c 87 [2] 58 89 [2] 73 a5 [2] 5d 87 [2] 49 9c [2] 46 86 [2] 58 9b [2] 5a 9a [2] 41 9c [2] 5d 9b [2] 41 b4 }

  condition:
    any of them
}