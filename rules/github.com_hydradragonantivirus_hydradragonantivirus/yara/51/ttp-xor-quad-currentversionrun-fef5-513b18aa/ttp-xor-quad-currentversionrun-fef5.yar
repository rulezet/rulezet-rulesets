rule TTP_XOR_QUAD_CurrentVersionRun_fef5 {
  strings:
    $key_fef5 = { ad 9a [2] 89 94 [2] a2 b8 [2] 8c 9a [2] 98 81 [2] 97 9b [2] 89 86 [2] 8b 87 [2] 90 81 [2] 8c 86 [2] 90 a9 }

  condition:
    any of them
}