rule TTP_XOR_QUAD_CurrentVersionRun_f42e {
  strings:
    $key_f42e = { a7 41 [2] 83 4f [2] a8 63 [2] 86 41 [2] 92 5a [2] 9d 40 [2] 83 5d [2] 81 5c [2] 9a 5a [2] 86 5d [2] 9a 72 }

  condition:
    any of them
}