rule TTP_XOR_QUAD_CurrentVersionRun_d26c {
  strings:
    $key_d26c = { 81 03 [2] a5 0d [2] 8e 21 [2] a0 03 [2] b4 18 [2] bb 02 [2] a5 1f [2] a7 1e [2] bc 18 [2] a0 1f [2] bc 30 }

  condition:
    any of them
}