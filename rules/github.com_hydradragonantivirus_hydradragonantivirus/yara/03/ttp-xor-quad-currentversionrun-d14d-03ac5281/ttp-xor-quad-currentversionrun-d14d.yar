rule TTP_XOR_QUAD_CurrentVersionRun_d14d {
  strings:
    $key_d14d = { 82 22 [2] a6 2c [2] 8d 00 [2] a3 22 [2] b7 39 [2] b8 23 [2] a6 3e [2] a4 3f [2] bf 39 [2] a3 3e [2] bf 11 }

  condition:
    any of them
}