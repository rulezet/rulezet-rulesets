rule TTP_XOR_QUAD_CurrentVersionRun_d12d {
  strings:
    $key_d12d = { 82 42 [2] a6 4c [2] 8d 60 [2] a3 42 [2] b7 59 [2] b8 43 [2] a6 5e [2] a4 5f [2] bf 59 [2] a3 5e [2] bf 71 }

  condition:
    any of them
}