rule TTP_XOR_QUAD_CurrentVersionRun_f75e {
  strings:
    $key_f75e = { a4 31 [2] 80 3f [2] ab 13 [2] 85 31 [2] 91 2a [2] 9e 30 [2] 80 2d [2] 82 2c [2] 99 2a [2] 85 2d [2] 99 02 }

  condition:
    any of them
}