rule TTP_XOR_QUAD_CurrentVersionRun_f75a {
  strings:
    $key_f75a = { a4 35 [2] 80 3b [2] ab 17 [2] 85 35 [2] 91 2e [2] 9e 34 [2] 80 29 [2] 82 28 [2] 99 2e [2] 85 29 [2] 99 06 }

  condition:
    any of them
}