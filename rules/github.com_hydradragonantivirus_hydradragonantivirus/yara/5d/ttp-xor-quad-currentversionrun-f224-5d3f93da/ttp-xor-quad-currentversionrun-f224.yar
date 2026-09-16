rule TTP_XOR_QUAD_CurrentVersionRun_f224 {
  strings:
    $key_f224 = { a1 4b [2] 85 45 [2] ae 69 [2] 80 4b [2] 94 50 [2] 9b 4a [2] 85 57 [2] 87 56 [2] 9c 50 [2] 80 57 [2] 9c 78 }

  condition:
    any of them
}