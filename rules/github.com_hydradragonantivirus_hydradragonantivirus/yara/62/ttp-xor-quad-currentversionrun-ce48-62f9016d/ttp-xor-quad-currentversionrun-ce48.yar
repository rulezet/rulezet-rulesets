rule TTP_XOR_QUAD_CurrentVersionRun_ce48 {
  strings:
    $key_ce48 = { 9d 27 [2] b9 29 [2] 92 05 [2] bc 27 [2] a8 3c [2] a7 26 [2] b9 3b [2] bb 3a [2] a0 3c [2] bc 3b [2] a0 14 }

  condition:
    any of them
}