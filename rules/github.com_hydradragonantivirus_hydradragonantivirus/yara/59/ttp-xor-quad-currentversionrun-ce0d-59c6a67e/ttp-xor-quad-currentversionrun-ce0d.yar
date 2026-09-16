rule TTP_XOR_QUAD_CurrentVersionRun_ce0d {
  strings:
    $key_ce0d = { 9d 62 [2] b9 6c [2] 92 40 [2] bc 62 [2] a8 79 [2] a7 63 [2] b9 7e [2] bb 7f [2] a0 79 [2] bc 7e [2] a0 51 }

  condition:
    any of them
}