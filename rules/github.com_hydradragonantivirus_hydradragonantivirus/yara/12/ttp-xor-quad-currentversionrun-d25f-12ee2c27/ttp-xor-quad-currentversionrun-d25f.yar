rule TTP_XOR_QUAD_CurrentVersionRun_d25f {
  strings:
    $key_d25f = { 81 30 [2] a5 3e [2] 8e 12 [2] a0 30 [2] b4 2b [2] bb 31 [2] a5 2c [2] a7 2d [2] bc 2b [2] a0 2c [2] bc 03 }

  condition:
    any of them
}