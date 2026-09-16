rule TTP_XOR_QUAD_CurrentVersionRun_ce30 {
  strings:
    $key_ce30 = { 9d 5f [2] b9 51 [2] 92 7d [2] bc 5f [2] a8 44 [2] a7 5e [2] b9 43 [2] bb 42 [2] a0 44 [2] bc 43 [2] a0 6c }

  condition:
    any of them
}