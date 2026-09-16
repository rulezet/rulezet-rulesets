rule TTP_XOR_QUAD_CurrentVersionRun_32f5 {
  strings:
    $key_32f5 = { 61 9a [2] 45 94 [2] 6e b8 [2] 40 9a [2] 54 81 [2] 5b 9b [2] 45 86 [2] 47 87 [2] 5c 81 [2] 40 86 [2] 5c a9 }

  condition:
    any of them
}