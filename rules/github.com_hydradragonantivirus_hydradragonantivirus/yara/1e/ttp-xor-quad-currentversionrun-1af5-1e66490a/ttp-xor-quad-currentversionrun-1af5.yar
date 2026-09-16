rule TTP_XOR_QUAD_CurrentVersionRun_1af5 {
  strings:
    $key_1af5 = { 49 9a [2] 6d 94 [2] 46 b8 [2] 68 9a [2] 7c 81 [2] 73 9b [2] 6d 86 [2] 6f 87 [2] 74 81 [2] 68 86 [2] 74 a9 }

  condition:
    any of them
}