rule TTP_XOR_QUAD_CurrentVersionRun_ce7a {
  strings:
    $key_ce7a = { 9d 15 [2] b9 1b [2] 92 37 [2] bc 15 [2] a8 0e [2] a7 14 [2] b9 09 [2] bb 08 [2] a0 0e [2] bc 09 [2] a0 26 }

  condition:
    any of them
}