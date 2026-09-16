rule TTP_XOR_QUAD_CurrentVersionRun_ce5f {
  strings:
    $key_ce5f = { 9d 30 [2] b9 3e [2] 92 12 [2] bc 30 [2] a8 2b [2] a7 31 [2] b9 2c [2] bb 2d [2] a0 2b [2] bc 2c [2] a0 03 }

  condition:
    any of them
}