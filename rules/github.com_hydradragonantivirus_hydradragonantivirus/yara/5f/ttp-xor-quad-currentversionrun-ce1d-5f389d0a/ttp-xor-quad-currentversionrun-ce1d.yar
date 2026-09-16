rule TTP_XOR_QUAD_CurrentVersionRun_ce1d {
  strings:
    $key_ce1d = { 9d 72 [2] b9 7c [2] 92 50 [2] bc 72 [2] a8 69 [2] a7 73 [2] b9 6e [2] bb 6f [2] a0 69 [2] bc 6e [2] a0 41 }

  condition:
    any of them
}