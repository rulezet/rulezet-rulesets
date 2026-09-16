rule TTP_XOR_QUAD_CurrentVersionRun_ce61 {
  strings:
    $key_ce61 = { 9d 0e [2] b9 00 [2] 92 2c [2] bc 0e [2] a8 15 [2] a7 0f [2] b9 12 [2] bb 13 [2] a0 15 [2] bc 12 [2] a0 3d }

  condition:
    any of them
}