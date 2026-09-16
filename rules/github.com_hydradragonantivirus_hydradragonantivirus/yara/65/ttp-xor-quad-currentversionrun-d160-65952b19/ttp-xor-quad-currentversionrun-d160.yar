rule TTP_XOR_QUAD_CurrentVersionRun_d160 {
  strings:
    $key_d160 = { 82 0f [2] a6 01 [2] 8d 2d [2] a3 0f [2] b7 14 [2] b8 0e [2] a6 13 [2] a4 12 [2] bf 14 [2] a3 13 [2] bf 3c }

  condition:
    any of them
}