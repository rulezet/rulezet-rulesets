rule TTP_XOR_QUAD_CurrentVersionRun_d24c {
  strings:
    $key_d24c = { 81 23 [2] a5 2d [2] 8e 01 [2] a0 23 [2] b4 38 [2] bb 22 [2] a5 3f [2] a7 3e [2] bc 38 [2] a0 3f [2] bc 10 }

  condition:
    any of them
}