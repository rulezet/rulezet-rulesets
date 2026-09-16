rule TTP_XOR_QUAD_CurrentVersionRun_f74e {
  strings:
    $key_f74e = { a4 21 [2] 80 2f [2] ab 03 [2] 85 21 [2] 91 3a [2] 9e 20 [2] 80 3d [2] 82 3c [2] 99 3a [2] 85 3d [2] 99 12 }

  condition:
    any of them
}