rule TTP_XOR_QUAD_CurrentVersionRun_f44c {
  strings:
    $key_f44c = { a7 23 [2] 83 2d [2] a8 01 [2] 86 23 [2] 92 38 [2] 9d 22 [2] 83 3f [2] 81 3e [2] 9a 38 [2] 86 3f [2] 9a 10 }

  condition:
    any of them
}