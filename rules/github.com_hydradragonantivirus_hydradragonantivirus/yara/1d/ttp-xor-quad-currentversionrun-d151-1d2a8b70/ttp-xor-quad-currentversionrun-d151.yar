rule TTP_XOR_QUAD_CurrentVersionRun_d151 {
  strings:
    $key_d151 = { 82 3e [2] a6 30 [2] 8d 1c [2] a3 3e [2] b7 25 [2] b8 3f [2] a6 22 [2] a4 23 [2] bf 25 [2] a3 22 [2] bf 0d }

  condition:
    any of them
}