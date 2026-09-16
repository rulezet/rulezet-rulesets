rule TTP_XOR_QUAD_CurrentVersionRun_f45f {
  strings:
    $key_f45f = { a7 30 [2] 83 3e [2] a8 12 [2] 86 30 [2] 92 2b [2] 9d 31 [2] 83 2c [2] 81 2d [2] 9a 2b [2] 86 2c [2] 9a 03 }

  condition:
    any of them
}