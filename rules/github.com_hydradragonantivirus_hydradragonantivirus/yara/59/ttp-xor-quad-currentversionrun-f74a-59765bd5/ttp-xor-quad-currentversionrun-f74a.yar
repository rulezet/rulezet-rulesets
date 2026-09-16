rule TTP_XOR_QUAD_CurrentVersionRun_f74a {
  strings:
    $key_f74a = { a4 25 [2] 80 2b [2] ab 07 [2] 85 25 [2] 91 3e [2] 9e 24 [2] 80 39 [2] 82 38 [2] 99 3e [2] 85 39 [2] 99 16 }

  condition:
    any of them
}