rule TTP_XOR_QUAD_CurrentVersionRun_f223 {
  strings:
    $key_f223 = { a1 4c [2] 85 42 [2] ae 6e [2] 80 4c [2] 94 57 [2] 9b 4d [2] 85 50 [2] 87 51 [2] 9c 57 [2] 80 50 [2] 9c 7f }

  condition:
    any of them
}