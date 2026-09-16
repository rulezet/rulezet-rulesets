rule TTP_XOR_QUAD_CurrentVersionRun_f74d {
  strings:
    $key_f74d = { a4 22 [2] 80 2c [2] ab 00 [2] 85 22 [2] 91 39 [2] 9e 23 [2] 80 3e [2] 82 3f [2] 99 39 [2] 85 3e [2] 99 11 }

  condition:
    any of them
}