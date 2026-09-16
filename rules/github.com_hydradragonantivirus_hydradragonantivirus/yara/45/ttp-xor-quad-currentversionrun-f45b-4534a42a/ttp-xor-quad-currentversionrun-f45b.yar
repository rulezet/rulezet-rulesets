rule TTP_XOR_QUAD_CurrentVersionRun_f45b {
  strings:
    $key_f45b = { a7 34 [2] 83 3a [2] a8 16 [2] 86 34 [2] 92 2f [2] 9d 35 [2] 83 28 [2] 81 29 [2] 9a 2f [2] 86 28 [2] 9a 07 }

  condition:
    any of them
}