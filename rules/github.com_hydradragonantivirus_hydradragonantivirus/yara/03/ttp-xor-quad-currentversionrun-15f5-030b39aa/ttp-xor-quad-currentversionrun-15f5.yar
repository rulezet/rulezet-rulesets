rule TTP_XOR_QUAD_CurrentVersionRun_15f5 {
  strings:
    $key_15f5 = { 46 9a [2] 62 94 [2] 49 b8 [2] 67 9a [2] 73 81 [2] 7c 9b [2] 62 86 [2] 60 87 [2] 7b 81 [2] 67 86 [2] 7b a9 }

  condition:
    any of them
}