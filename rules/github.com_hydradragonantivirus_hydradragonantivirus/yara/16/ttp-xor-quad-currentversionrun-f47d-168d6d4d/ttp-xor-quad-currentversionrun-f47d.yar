rule TTP_XOR_QUAD_CurrentVersionRun_f47d {
  strings:
    $key_f47d = { a7 12 [2] 83 1c [2] a8 30 [2] 86 12 [2] 92 09 [2] 9d 13 [2] 83 0e [2] 81 0f [2] 9a 09 [2] 86 0e [2] 9a 21 }

  condition:
    any of them
}