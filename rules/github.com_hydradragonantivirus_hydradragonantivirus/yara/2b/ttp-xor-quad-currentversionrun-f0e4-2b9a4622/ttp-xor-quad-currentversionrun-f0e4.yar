rule TTP_XOR_QUAD_CurrentVersionRun_f0e4 {
  strings:
    $key_f0e4 = { a3 8b [2] 87 85 [2] ac a9 [2] 82 8b [2] 96 90 [2] 99 8a [2] 87 97 [2] 85 96 [2] 9e 90 [2] 82 97 [2] 9e b8 }

  condition:
    any of them
}