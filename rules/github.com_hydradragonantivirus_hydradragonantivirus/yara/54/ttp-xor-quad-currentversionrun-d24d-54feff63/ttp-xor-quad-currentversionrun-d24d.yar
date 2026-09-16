rule TTP_XOR_QUAD_CurrentVersionRun_d24d {
  strings:
    $key_d24d = { 81 22 [2] a5 2c [2] 8e 00 [2] a0 22 [2] b4 39 [2] bb 23 [2] a5 3e [2] a7 3f [2] bc 39 [2] a0 3e [2] bc 11 }

  condition:
    any of them
}