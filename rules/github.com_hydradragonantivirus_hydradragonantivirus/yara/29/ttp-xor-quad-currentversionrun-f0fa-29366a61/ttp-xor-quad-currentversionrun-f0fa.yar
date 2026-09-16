rule TTP_XOR_QUAD_CurrentVersionRun_f0fa {
  strings:
    $key_f0fa = { a3 95 [2] 87 9b [2] ac b7 [2] 82 95 [2] 96 8e [2] 99 94 [2] 87 89 [2] 85 88 [2] 9e 8e [2] 82 89 [2] 9e a6 }

  condition:
    any of them
}