rule TTP_XOR_QUAD_CurrentVersionRun_f77f {
  strings:
    $key_f77f = { a4 10 [2] 80 1e [2] ab 32 [2] 85 10 [2] 91 0b [2] 9e 11 [2] 80 0c [2] 82 0d [2] 99 0b [2] 85 0c [2] 99 23 }

  condition:
    any of them
}