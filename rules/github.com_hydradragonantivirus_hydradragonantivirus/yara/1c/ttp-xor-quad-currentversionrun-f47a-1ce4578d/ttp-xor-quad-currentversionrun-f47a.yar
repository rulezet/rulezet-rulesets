rule TTP_XOR_QUAD_CurrentVersionRun_f47a {
  strings:
    $key_f47a = { a7 15 [2] 83 1b [2] a8 37 [2] 86 15 [2] 92 0e [2] 9d 14 [2] 83 09 [2] 81 08 [2] 9a 0e [2] 86 09 [2] 9a 26 }

  condition:
    any of them
}