rule TTP_XOR_QUAD_CurrentVersionRun_d123 {
  strings:
    $key_d123 = { 82 4c [2] a6 42 [2] 8d 6e [2] a3 4c [2] b7 57 [2] b8 4d [2] a6 50 [2] a4 51 [2] bf 57 [2] a3 50 [2] bf 7f }

  condition:
    any of them
}