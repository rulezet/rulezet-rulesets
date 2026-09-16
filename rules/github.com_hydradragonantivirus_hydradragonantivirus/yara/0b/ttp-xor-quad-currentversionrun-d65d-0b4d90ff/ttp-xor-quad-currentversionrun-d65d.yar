rule TTP_XOR_QUAD_CurrentVersionRun_d65d {
  strings:
    $key_d65d = { 85 32 [2] a1 3c [2] 8a 10 [2] a4 32 [2] b0 29 [2] bf 33 [2] a1 2e [2] a3 2f [2] b8 29 [2] a4 2e [2] b8 01 }

  condition:
    any of them
}