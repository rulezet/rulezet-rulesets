rule TTP_XOR_QUAD_CurrentVersionRun_f50a {
  strings:
    $key_f50a = { a6 65 [2] 82 6b [2] a9 47 [2] 87 65 [2] 93 7e [2] 9c 64 [2] 82 79 [2] 80 78 [2] 9b 7e [2] 87 79 [2] 9b 56 }

  condition:
    any of them
}