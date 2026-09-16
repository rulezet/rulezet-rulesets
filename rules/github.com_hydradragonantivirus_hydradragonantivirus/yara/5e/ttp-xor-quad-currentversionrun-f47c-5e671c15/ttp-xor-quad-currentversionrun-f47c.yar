rule TTP_XOR_QUAD_CurrentVersionRun_f47c {
  strings:
    $key_f47c = { a7 13 [2] 83 1d [2] a8 31 [2] 86 13 [2] 92 08 [2] 9d 12 [2] 83 0f [2] 81 0e [2] 9a 08 [2] 86 0f [2] 9a 20 }

  condition:
    any of them
}