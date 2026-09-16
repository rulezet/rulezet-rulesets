rule TTP_XOR_QUAD_CurrentVersionRun_d141 {
  strings:
    $key_d141 = { 82 2e [2] a6 20 [2] 8d 0c [2] a3 2e [2] b7 35 [2] b8 2f [2] a6 32 [2] a4 33 [2] bf 35 [2] a3 32 [2] bf 1d }

  condition:
    any of them
}