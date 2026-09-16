rule TTP_XOR_QUAD_CurrentVersionRun_f363 {
  strings:
    $key_f363 = { a0 0c [2] 84 02 [2] af 2e [2] 81 0c [2] 95 17 [2] 9a 0d [2] 84 10 [2] 86 11 [2] 9d 17 [2] 81 10 [2] 9d 3f }

  condition:
    any of them
}