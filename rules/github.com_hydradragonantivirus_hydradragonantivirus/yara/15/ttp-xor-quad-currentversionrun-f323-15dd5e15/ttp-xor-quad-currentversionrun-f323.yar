rule TTP_XOR_QUAD_CurrentVersionRun_f323 {
  strings:
    $key_f323 = { a0 4c [2] 84 42 [2] af 6e [2] 81 4c [2] 95 57 [2] 9a 4d [2] 84 50 [2] 86 51 [2] 9d 57 [2] 81 50 [2] 9d 7f }

  condition:
    any of them
}