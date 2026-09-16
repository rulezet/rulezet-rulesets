rule TTP_XOR_QUAD_CurrentVersionRun_d15d {
  strings:
    $key_d15d = { 82 32 [2] a6 3c [2] 8d 10 [2] a3 32 [2] b7 29 [2] b8 33 [2] a6 2e [2] a4 2f [2] bf 29 [2] a3 2e [2] bf 01 }

  condition:
    any of them
}