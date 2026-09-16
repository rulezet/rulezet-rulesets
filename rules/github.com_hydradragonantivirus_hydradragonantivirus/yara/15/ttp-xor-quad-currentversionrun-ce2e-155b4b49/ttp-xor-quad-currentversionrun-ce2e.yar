rule TTP_XOR_QUAD_CurrentVersionRun_ce2e {
  strings:
    $key_ce2e = { 9d 41 [2] b9 4f [2] 92 63 [2] bc 41 [2] a8 5a [2] a7 40 [2] b9 5d [2] bb 5c [2] a0 5a [2] bc 5d [2] a0 72 }

  condition:
    any of them
}