rule TTP_XOR_QUAD_CurrentVersionRun_f52a {
  strings:
    $key_f52a = { a6 45 [2] 82 4b [2] a9 67 [2] 87 45 [2] 93 5e [2] 9c 44 [2] 82 59 [2] 80 58 [2] 9b 5e [2] 87 59 [2] 9b 76 }

  condition:
    any of them
}