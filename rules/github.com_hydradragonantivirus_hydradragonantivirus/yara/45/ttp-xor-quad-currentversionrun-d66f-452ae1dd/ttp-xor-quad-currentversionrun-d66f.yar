rule TTP_XOR_QUAD_CurrentVersionRun_d66f {
  strings:
    $key_d66f = { 85 00 [2] a1 0e [2] 8a 22 [2] a4 00 [2] b0 1b [2] bf 01 [2] a1 1c [2] a3 1d [2] b8 1b [2] a4 1c [2] b8 33 }

  condition:
    any of them
}