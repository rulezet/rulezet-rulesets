rule TTP_XOR_QUAD_CurrentVersionRun_ce70 {
  strings:
    $key_ce70 = { 9d 1f [2] b9 11 [2] 92 3d [2] bc 1f [2] a8 04 [2] a7 1e [2] b9 03 [2] bb 02 [2] a0 04 [2] bc 03 [2] a0 2c }

  condition:
    any of them
}