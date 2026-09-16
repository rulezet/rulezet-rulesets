rule TTP_XOR_QUAD_CurrentVersionRun_f0e5 {
  strings:
    $key_f0e5 = { a3 8a [2] 87 84 [2] ac a8 [2] 82 8a [2] 96 91 [2] 99 8b [2] 87 96 [2] 85 97 [2] 9e 91 [2] 82 96 [2] 9e b9 }

  condition:
    any of them
}