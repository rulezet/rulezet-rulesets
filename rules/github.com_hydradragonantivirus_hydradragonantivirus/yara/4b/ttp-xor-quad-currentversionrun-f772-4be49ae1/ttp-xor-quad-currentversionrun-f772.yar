rule TTP_XOR_QUAD_CurrentVersionRun_f772 {
  strings:
    $key_f772 = { a4 1d [2] 80 13 [2] ab 3f [2] 85 1d [2] 91 06 [2] 9e 1c [2] 80 01 [2] 82 00 [2] 99 06 [2] 85 01 [2] 99 2e }

  condition:
    any of them
}