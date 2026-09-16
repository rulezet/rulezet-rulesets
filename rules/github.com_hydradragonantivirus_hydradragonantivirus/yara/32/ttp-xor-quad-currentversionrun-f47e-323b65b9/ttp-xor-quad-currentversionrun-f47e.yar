rule TTP_XOR_QUAD_CurrentVersionRun_f47e {
  strings:
    $key_f47e = { a7 11 [2] 83 1f [2] a8 33 [2] 86 11 [2] 92 0a [2] 9d 10 [2] 83 0d [2] 81 0c [2] 9a 0a [2] 86 0d [2] 9a 22 }

  condition:
    any of them
}