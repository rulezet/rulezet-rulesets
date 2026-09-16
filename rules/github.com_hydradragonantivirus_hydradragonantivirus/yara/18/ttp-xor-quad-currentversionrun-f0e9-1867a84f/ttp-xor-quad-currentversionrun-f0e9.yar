rule TTP_XOR_QUAD_CurrentVersionRun_f0e9 {
  strings:
    $key_f0e9 = { a3 86 [2] 87 88 [2] ac a4 [2] 82 86 [2] 96 9d [2] 99 87 [2] 87 9a [2] 85 9b [2] 9e 9d [2] 82 9a [2] 9e b5 }

  condition:
    any of them
}