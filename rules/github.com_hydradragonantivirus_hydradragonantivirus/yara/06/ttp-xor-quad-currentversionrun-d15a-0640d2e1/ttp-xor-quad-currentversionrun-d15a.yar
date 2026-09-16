rule TTP_XOR_QUAD_CurrentVersionRun_d15a {
  strings:
    $key_d15a = { 82 35 [2] a6 3b [2] 8d 17 [2] a3 35 [2] b7 2e [2] b8 34 [2] a6 29 [2] a4 28 [2] bf 2e [2] a3 29 [2] bf 06 }

  condition:
    any of them
}