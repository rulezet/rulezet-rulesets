rule TTP_XOR_QUAD_CurrentVersionRun_d142 {
  strings:
    $key_d142 = { 82 2d [2] a6 23 [2] 8d 0f [2] a3 2d [2] b7 36 [2] b8 2c [2] a6 31 [2] a4 30 [2] bf 36 [2] a3 31 [2] bf 1e }

  condition:
    any of them
}