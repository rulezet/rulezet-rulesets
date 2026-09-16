rule TTP_XOR_QUAD_CurrentVersionRun_ce2a {
  strings:
    $key_ce2a = { 9d 45 [2] b9 4b [2] 92 67 [2] bc 45 [2] a8 5e [2] a7 44 [2] b9 59 [2] bb 58 [2] a0 5e [2] bc 59 [2] a0 76 }

  condition:
    any of them
}