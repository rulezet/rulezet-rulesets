rule TTP_XOR_QUAD_CurrentVersionRun_f4ef {
  strings:
    $key_f4ef = { a7 80 [2] 83 8e [2] a8 a2 [2] 86 80 [2] 92 9b [2] 9d 81 [2] 83 9c [2] 81 9d [2] 9a 9b [2] 86 9c [2] 9a b3 }

  condition:
    any of them
}