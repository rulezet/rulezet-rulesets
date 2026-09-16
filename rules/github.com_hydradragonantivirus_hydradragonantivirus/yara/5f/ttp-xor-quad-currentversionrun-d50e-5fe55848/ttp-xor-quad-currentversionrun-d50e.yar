rule TTP_XOR_QUAD_CurrentVersionRun_d50e {
  strings:
    $key_d50e = { 86 61 [2] a2 6f [2] 89 43 [2] a7 61 [2] b3 7a [2] bc 60 [2] a2 7d [2] a0 7c [2] bb 7a [2] a7 7d [2] bb 52 }

  condition:
    any of them
}