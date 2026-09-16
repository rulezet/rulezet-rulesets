rule TTP_XOR_QUAD_CurrentVersionRun_2bf5 {
  strings:
    $key_2bf5 = { 78 9a [2] 5c 94 [2] 77 b8 [2] 59 9a [2] 4d 81 [2] 42 9b [2] 5c 86 [2] 5e 87 [2] 45 81 [2] 59 86 [2] 45 a9 }

  condition:
    any of them
}