rule TTP_XOR_QUAD_CurrentVersionRun_f504 {
  strings:
    $key_f504 = { a6 6b [2] 82 65 [2] a9 49 [2] 87 6b [2] 93 70 [2] 9c 6a [2] 82 77 [2] 80 76 [2] 9b 70 [2] 87 77 [2] 9b 58 }

  condition:
    any of them
}