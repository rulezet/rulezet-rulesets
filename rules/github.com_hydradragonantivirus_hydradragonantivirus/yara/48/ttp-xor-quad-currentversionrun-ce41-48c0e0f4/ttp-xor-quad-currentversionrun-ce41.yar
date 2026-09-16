rule TTP_XOR_QUAD_CurrentVersionRun_ce41 {
  strings:
    $key_ce41 = { 9d 2e [2] b9 20 [2] 92 0c [2] bc 2e [2] a8 35 [2] a7 2f [2] b9 32 [2] bb 33 [2] a0 35 [2] bc 32 [2] a0 1d }

  condition:
    any of them
}