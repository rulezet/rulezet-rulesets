rule TTP_XOR_QUAD_CurrentVersionRun_f17e {
  strings:
    $key_f17e = { a2 11 [2] 86 1f [2] ad 33 [2] 83 11 [2] 97 0a [2] 98 10 [2] 86 0d [2] 84 0c [2] 9f 0a [2] 83 0d [2] 9f 22 }

  condition:
    any of them
}