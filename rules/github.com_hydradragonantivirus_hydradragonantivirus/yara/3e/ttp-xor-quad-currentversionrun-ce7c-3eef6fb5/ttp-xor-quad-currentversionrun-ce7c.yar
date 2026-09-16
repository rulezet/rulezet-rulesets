rule TTP_XOR_QUAD_CurrentVersionRun_ce7c {
  strings:
    $key_ce7c = { 9d 13 [2] b9 1d [2] 92 31 [2] bc 13 [2] a8 08 [2] a7 12 [2] b9 0f [2] bb 0e [2] a0 08 [2] bc 0f [2] a0 20 }

  condition:
    any of them
}