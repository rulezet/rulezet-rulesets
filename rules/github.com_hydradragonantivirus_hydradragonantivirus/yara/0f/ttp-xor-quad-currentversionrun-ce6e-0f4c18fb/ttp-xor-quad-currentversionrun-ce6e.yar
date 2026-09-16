rule TTP_XOR_QUAD_CurrentVersionRun_ce6e {
  strings:
    $key_ce6e = { 9d 01 [2] b9 0f [2] 92 23 [2] bc 01 [2] a8 1a [2] a7 00 [2] b9 1d [2] bb 1c [2] a0 1a [2] bc 1d [2] a0 32 }

  condition:
    any of them
}