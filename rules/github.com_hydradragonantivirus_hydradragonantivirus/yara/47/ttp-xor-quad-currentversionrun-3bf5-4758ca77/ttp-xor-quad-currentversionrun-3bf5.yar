rule TTP_XOR_QUAD_CurrentVersionRun_3bf5 {
  strings:
    $key_3bf5 = { 68 9a [2] 4c 94 [2] 67 b8 [2] 49 9a [2] 5d 81 [2] 52 9b [2] 4c 86 [2] 4e 87 [2] 55 81 [2] 49 86 [2] 55 a9 }

  condition:
    any of them
}