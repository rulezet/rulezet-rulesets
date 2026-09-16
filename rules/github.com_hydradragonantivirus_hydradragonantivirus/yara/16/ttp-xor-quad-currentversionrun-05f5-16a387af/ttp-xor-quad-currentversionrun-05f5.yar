rule TTP_XOR_QUAD_CurrentVersionRun_05f5 {
  strings:
    $key_05f5 = { 56 9a [2] 72 94 [2] 59 b8 [2] 77 9a [2] 63 81 [2] 6c 9b [2] 72 86 [2] 70 87 [2] 6b 81 [2] 77 86 [2] 6b a9 }

  condition:
    any of them
}