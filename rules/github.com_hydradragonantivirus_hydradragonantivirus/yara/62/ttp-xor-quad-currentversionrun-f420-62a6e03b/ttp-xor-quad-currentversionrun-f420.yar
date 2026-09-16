rule TTP_XOR_QUAD_CurrentVersionRun_f420 {
  strings:
    $key_f420 = { a7 4f [2] 83 41 [2] a8 6d [2] 86 4f [2] 92 54 [2] 9d 4e [2] 83 53 [2] 81 52 [2] 9a 54 [2] 86 53 [2] 9a 7c }

  condition:
    any of them
}