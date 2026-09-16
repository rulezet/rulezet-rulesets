rule TTP_XOR_QUAD_CurrentVersionRun_34f5 {
  strings:
    $key_34f5 = { 67 9a [2] 43 94 [2] 68 b8 [2] 46 9a [2] 52 81 [2] 5d 9b [2] 43 86 [2] 41 87 [2] 5a 81 [2] 46 86 [2] 5a a9 }

  condition:
    any of them
}