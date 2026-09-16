rule TTP_XOR_QUAD_CurrentVersionRun_f77d {
  strings:
    $key_f77d = { a4 12 [2] 80 1c [2] ab 30 [2] 85 12 [2] 91 09 [2] 9e 13 [2] 80 0e [2] 82 0f [2] 99 09 [2] 85 0e [2] 99 21 }

  condition:
    any of them
}