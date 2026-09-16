rule TTP_XOR_QUAD_CurrentVersionRun_f67e {
  strings:
    $key_f67e = { a5 11 [2] 81 1f [2] aa 33 [2] 84 11 [2] 90 0a [2] 9f 10 [2] 81 0d [2] 83 0c [2] 98 0a [2] 84 0d [2] 98 22 }

  condition:
    any of them
}