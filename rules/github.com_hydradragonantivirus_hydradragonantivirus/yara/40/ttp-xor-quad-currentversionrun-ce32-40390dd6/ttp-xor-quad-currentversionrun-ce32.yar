rule TTP_XOR_QUAD_CurrentVersionRun_ce32 {
  strings:
    $key_ce32 = { 9d 5d [2] b9 53 [2] 92 7f [2] bc 5d [2] a8 46 [2] a7 5c [2] b9 41 [2] bb 40 [2] a0 46 [2] bc 41 [2] a0 6e }

  condition:
    any of them
}