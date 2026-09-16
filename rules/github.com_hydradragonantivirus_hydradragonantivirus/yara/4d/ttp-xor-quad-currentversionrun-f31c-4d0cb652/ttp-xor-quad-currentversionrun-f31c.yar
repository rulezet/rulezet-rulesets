rule TTP_XOR_QUAD_CurrentVersionRun_f31c {
  strings:
    $key_f31c = { a0 73 [2] 84 7d [2] af 51 [2] 81 73 [2] 95 68 [2] 9a 72 [2] 84 6f [2] 86 6e [2] 9d 68 [2] 81 6f [2] 9d 40 }

  condition:
    any of them
}