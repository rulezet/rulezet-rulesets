rule TTP_XOR_QUAD_CurrentVersionRun_f400 {
  strings:
    $key_f400 = { a7 6f [2] 83 61 [2] a8 4d [2] 86 6f [2] 92 74 [2] 9d 6e [2] 83 73 [2] 81 72 [2] 9a 74 [2] 86 73 [2] 9a 5c }

  condition:
    any of them
}