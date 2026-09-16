rule TTP_XOR_QUAD_CurrentVersionRun_d1ed {
  strings:
    $key_d1ed = { 82 82 [2] a6 8c [2] 8d a0 [2] a3 82 [2] b7 99 [2] b8 83 [2] a6 9e [2] a4 9f [2] bf 99 [2] a3 9e [2] bf b1 }

  condition:
    any of them
}