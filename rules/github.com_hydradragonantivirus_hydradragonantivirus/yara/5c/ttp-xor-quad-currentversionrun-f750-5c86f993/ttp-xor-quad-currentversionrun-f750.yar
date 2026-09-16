rule TTP_XOR_QUAD_CurrentVersionRun_f750 {
  strings:
    $key_f750 = { a4 3f [2] 80 31 [2] ab 1d [2] 85 3f [2] 91 24 [2] 9e 3e [2] 80 23 [2] 82 22 [2] 99 24 [2] 85 23 [2] 99 0c }

  condition:
    any of them
}