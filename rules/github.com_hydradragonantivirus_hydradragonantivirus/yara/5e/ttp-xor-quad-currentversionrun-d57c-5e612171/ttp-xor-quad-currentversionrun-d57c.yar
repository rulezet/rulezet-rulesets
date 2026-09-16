rule TTP_XOR_QUAD_CurrentVersionRun_d57c {
  strings:
    $key_d57c = { 86 13 [2] a2 1d [2] 89 31 [2] a7 13 [2] b3 08 [2] bc 12 [2] a2 0f [2] a0 0e [2] bb 08 [2] a7 0f [2] bb 20 }

  condition:
    any of them
}