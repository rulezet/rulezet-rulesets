rule TTP_XOR_QUAD_CurrentVersionRun_f31d {
  strings:
    $key_f31d = { a0 72 [2] 84 7c [2] af 50 [2] 81 72 [2] 95 69 [2] 9a 73 [2] 84 6e [2] 86 6f [2] 9d 69 [2] 81 6e [2] 9d 41 }

  condition:
    any of them
}