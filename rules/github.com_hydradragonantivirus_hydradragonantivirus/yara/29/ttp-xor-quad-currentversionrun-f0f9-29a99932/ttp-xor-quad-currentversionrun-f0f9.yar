rule TTP_XOR_QUAD_CurrentVersionRun_f0f9 {
  strings:
    $key_f0f9 = { a3 96 [2] 87 98 [2] ac b4 [2] 82 96 [2] 96 8d [2] 99 97 [2] 87 8a [2] 85 8b [2] 9e 8d [2] 82 8a [2] 9e a5 }

  condition:
    any of them
}