rule TTP_XOR_QUAD_CurrentVersionRun_d270 {
  strings:
    $key_d270 = { 81 1f [2] a5 11 [2] 8e 3d [2] a0 1f [2] b4 04 [2] bb 1e [2] a5 03 [2] a7 02 [2] bc 04 [2] a0 03 [2] bc 2c }

  condition:
    any of them
}