rule TTP_XOR_QUAD_CurrentVersionRun_ce01 {
  strings:
    $key_ce01 = { 9d 6e [2] b9 60 [2] 92 4c [2] bc 6e [2] a8 75 [2] a7 6f [2] b9 72 [2] bb 73 [2] a0 75 [2] bc 72 [2] a0 5d }

  condition:
    any of them
}