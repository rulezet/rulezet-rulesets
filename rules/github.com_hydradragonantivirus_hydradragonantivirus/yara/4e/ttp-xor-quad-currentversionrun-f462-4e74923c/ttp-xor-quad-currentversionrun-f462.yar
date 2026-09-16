rule TTP_XOR_QUAD_CurrentVersionRun_f462 {
  strings:
    $key_f462 = { a7 0d [2] 83 03 [2] a8 2f [2] 86 0d [2] 92 16 [2] 9d 0c [2] 83 11 [2] 81 10 [2] 9a 16 [2] 86 11 [2] 9a 3e }

  condition:
    any of them
}