rule TTP_XOR_QUAD_CurrentVersionRun_f5ef {
  strings:
    $key_f5ef = { a6 80 [2] 82 8e [2] a9 a2 [2] 87 80 [2] 93 9b [2] 9c 81 [2] 82 9c [2] 80 9d [2] 9b 9b [2] 87 9c [2] 9b b3 }

  condition:
    any of them
}