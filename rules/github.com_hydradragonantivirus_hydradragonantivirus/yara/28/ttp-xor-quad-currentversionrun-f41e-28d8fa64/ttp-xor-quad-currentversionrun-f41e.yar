rule TTP_XOR_QUAD_CurrentVersionRun_f41e {
  strings:
    $key_f41e = { a7 71 [2] 83 7f [2] a8 53 [2] 86 71 [2] 92 6a [2] 9d 70 [2] 83 6d [2] 81 6c [2] 9a 6a [2] 86 6d [2] 9a 42 }

  condition:
    any of them
}