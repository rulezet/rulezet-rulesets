rule TTP_XOR_QUAD_CurrentVersionRun_f75b {
  strings:
    $key_f75b = { a4 34 [2] 80 3a [2] ab 16 [2] 85 34 [2] 91 2f [2] 9e 35 [2] 80 28 [2] 82 29 [2] 99 2f [2] 85 28 [2] 99 07 }

  condition:
    any of them
}