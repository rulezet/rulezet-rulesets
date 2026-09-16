rule TTP_XOR_QUAD_CurrentVersionRun_f45c {
  strings:
    $key_f45c = { a7 33 [2] 83 3d [2] a8 11 [2] 86 33 [2] 92 28 [2] 9d 32 [2] 83 2f [2] 81 2e [2] 9a 28 [2] 86 2f [2] 9a 00 }

  condition:
    any of them
}