rule TTP_XOR_QUAD_CurrentVersionRun_f4fd {
  strings:
    $key_f4fd = { a7 92 [2] 83 9c [2] a8 b0 [2] 86 92 [2] 92 89 [2] 9d 93 [2] 83 8e [2] 81 8f [2] 9a 89 [2] 86 8e [2] 9a a1 }

  condition:
    any of them
}