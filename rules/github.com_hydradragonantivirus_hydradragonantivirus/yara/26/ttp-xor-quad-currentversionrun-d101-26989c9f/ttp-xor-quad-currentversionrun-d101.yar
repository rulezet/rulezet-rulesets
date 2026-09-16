rule TTP_XOR_QUAD_CurrentVersionRun_d101 {
  strings:
    $key_d101 = { 82 6e [2] a6 60 [2] 8d 4c [2] a3 6e [2] b7 75 [2] b8 6f [2] a6 72 [2] a4 73 [2] bf 75 [2] a3 72 [2] bf 5d }

  condition:
    any of them
}