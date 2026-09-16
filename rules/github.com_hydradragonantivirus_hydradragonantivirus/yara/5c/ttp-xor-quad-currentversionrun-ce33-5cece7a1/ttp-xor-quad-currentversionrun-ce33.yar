rule TTP_XOR_QUAD_CurrentVersionRun_ce33 {
  strings:
    $key_ce33 = { 9d 5c [2] b9 52 [2] 92 7e [2] bc 5c [2] a8 47 [2] a7 5d [2] b9 40 [2] bb 41 [2] a0 47 [2] bc 40 [2] a0 6f }

  condition:
    any of them
}