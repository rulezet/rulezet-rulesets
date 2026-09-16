rule TTP_XOR_QUAD_CurrentVersionRun_ce71 {
  strings:
    $key_ce71 = { 9d 1e [2] b9 10 [2] 92 3c [2] bc 1e [2] a8 05 [2] a7 1f [2] b9 02 [2] bb 03 [2] a0 05 [2] bc 02 [2] a0 2d }

  condition:
    any of them
}