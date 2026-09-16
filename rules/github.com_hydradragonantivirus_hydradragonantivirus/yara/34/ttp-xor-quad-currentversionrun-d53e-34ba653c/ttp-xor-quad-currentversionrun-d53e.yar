rule TTP_XOR_QUAD_CurrentVersionRun_d53e {
  strings:
    $key_d53e = { 86 51 [2] a2 5f [2] 89 73 [2] a7 51 [2] b3 4a [2] bc 50 [2] a2 4d [2] a0 4c [2] bb 4a [2] a7 4d [2] bb 62 }

  condition:
    any of them
}