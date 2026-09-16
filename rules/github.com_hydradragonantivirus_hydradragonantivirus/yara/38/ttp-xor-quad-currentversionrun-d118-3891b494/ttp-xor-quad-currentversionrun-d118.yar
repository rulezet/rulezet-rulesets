rule TTP_XOR_QUAD_CurrentVersionRun_d118 {
  strings:
    $key_d118 = { 82 77 [2] a6 79 [2] 8d 55 [2] a3 77 [2] b7 6c [2] b8 76 [2] a6 6b [2] a4 6a [2] bf 6c [2] a3 6b [2] bf 44 }

  condition:
    any of them
}