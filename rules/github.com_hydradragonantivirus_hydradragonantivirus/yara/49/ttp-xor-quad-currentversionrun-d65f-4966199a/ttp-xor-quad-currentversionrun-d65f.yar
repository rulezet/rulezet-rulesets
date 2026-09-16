rule TTP_XOR_QUAD_CurrentVersionRun_d65f {
  strings:
    $key_d65f = { 85 30 [2] a1 3e [2] 8a 12 [2] a4 30 [2] b0 2b [2] bf 31 [2] a1 2c [2] a3 2d [2] b8 2b [2] a4 2c [2] b8 03 }

  condition:
    any of them
}