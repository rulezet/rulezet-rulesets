rule TTP_XOR_QUAD_CurrentVersionRun_d161 {
  strings:
    $key_d161 = { 82 0e [2] a6 00 [2] 8d 2c [2] a3 0e [2] b7 15 [2] b8 0f [2] a6 12 [2] a4 13 [2] bf 15 [2] a3 12 [2] bf 3d }

  condition:
    any of them
}