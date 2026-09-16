rule TTP_XOR_QUAD_CurrentVersionRun_d65c {
  strings:
    $key_d65c = { 85 33 [2] a1 3d [2] 8a 11 [2] a4 33 [2] b0 28 [2] bf 32 [2] a1 2f [2] a3 2e [2] b8 28 [2] a4 2f [2] b8 00 }

  condition:
    any of them
}