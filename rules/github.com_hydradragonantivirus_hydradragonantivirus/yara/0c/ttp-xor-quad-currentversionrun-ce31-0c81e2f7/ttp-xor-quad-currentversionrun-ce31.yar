rule TTP_XOR_QUAD_CurrentVersionRun_ce31 {
  strings:
    $key_ce31 = { 9d 5e [2] b9 50 [2] 92 7c [2] bc 5e [2] a8 45 [2] a7 5f [2] b9 42 [2] bb 43 [2] a0 45 [2] bc 42 [2] a0 6d }

  condition:
    any of them
}