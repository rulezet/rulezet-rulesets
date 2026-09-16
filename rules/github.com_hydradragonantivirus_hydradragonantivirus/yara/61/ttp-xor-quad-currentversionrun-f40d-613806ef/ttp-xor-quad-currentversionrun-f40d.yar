rule TTP_XOR_QUAD_CurrentVersionRun_f40d {
  strings:
    $key_f40d = { a7 62 [2] 83 6c [2] a8 40 [2] 86 62 [2] 92 79 [2] 9d 63 [2] 83 7e [2] 81 7f [2] 9a 79 [2] 86 7e [2] 9a 51 }

  condition:
    any of them
}