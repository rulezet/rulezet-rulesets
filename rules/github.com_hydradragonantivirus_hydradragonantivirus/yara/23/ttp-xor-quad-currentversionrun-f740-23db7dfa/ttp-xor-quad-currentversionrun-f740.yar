rule TTP_XOR_QUAD_CurrentVersionRun_f740 {
  strings:
    $key_f740 = { a4 2f [2] 80 21 [2] ab 0d [2] 85 2f [2] 91 34 [2] 9e 2e [2] 80 33 [2] 82 32 [2] 99 34 [2] 85 33 [2] 99 1c }

  condition:
    any of them
}