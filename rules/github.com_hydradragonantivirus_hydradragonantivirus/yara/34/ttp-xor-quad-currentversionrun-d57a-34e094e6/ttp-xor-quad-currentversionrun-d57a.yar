rule TTP_XOR_QUAD_CurrentVersionRun_d57a {
  strings:
    $key_d57a = { 86 15 [2] a2 1b [2] 89 37 [2] a7 15 [2] b3 0e [2] bc 14 [2] a2 09 [2] a0 08 [2] bb 0e [2] a7 09 [2] bb 26 }

  condition:
    any of them
}