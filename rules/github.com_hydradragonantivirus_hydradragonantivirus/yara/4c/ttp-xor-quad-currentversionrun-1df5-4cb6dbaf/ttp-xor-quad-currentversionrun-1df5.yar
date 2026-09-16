rule TTP_XOR_QUAD_CurrentVersionRun_1df5 {
  strings:
    $key_1df5 = { 4e 9a [2] 6a 94 [2] 41 b8 [2] 6f 9a [2] 7b 81 [2] 74 9b [2] 6a 86 [2] 68 87 [2] 73 81 [2] 6f 86 [2] 73 a9 }

  condition:
    any of them
}