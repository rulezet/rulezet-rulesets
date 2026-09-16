rule TTP_XOR_QUAD_CurrentVersionRun_d131 {
  strings:
    $key_d131 = { 82 5e [2] a6 50 [2] 8d 7c [2] a3 5e [2] b7 45 [2] b8 5f [2] a6 42 [2] a4 43 [2] bf 45 [2] a3 42 [2] bf 6d }

  condition:
    any of them
}