rule TTP_XOR_QUAD_CurrentVersionRun_0bf5 {
  strings:
    $key_0bf5 = { 58 9a [2] 7c 94 [2] 57 b8 [2] 79 9a [2] 6d 81 [2] 62 9b [2] 7c 86 [2] 7e 87 [2] 65 81 [2] 79 86 [2] 65 a9 }

  condition:
    any of them
}