rule TTP_XOR_QUAD_CurrentVersionRun_f763 {
  strings:
    $key_f763 = { a4 0c [2] 80 02 [2] ab 2e [2] 85 0c [2] 91 17 [2] 9e 0d [2] 80 10 [2] 82 11 [2] 99 17 [2] 85 10 [2] 99 3f }

  condition:
    any of them
}