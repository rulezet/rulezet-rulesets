rule TTP_XOR_QUAD_CurrentVersionRun_f77e {
  strings:
    $key_f77e = { a4 11 [2] 80 1f [2] ab 33 [2] 85 11 [2] 91 0a [2] 9e 10 [2] 80 0d [2] 82 0c [2] 99 0a [2] 85 0d [2] 99 22 }

  condition:
    any of them
}