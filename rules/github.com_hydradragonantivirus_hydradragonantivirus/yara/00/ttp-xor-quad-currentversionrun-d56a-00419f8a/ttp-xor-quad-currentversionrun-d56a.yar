rule TTP_XOR_QUAD_CurrentVersionRun_d56a {
  strings:
    $key_d56a = { 86 05 [2] a2 0b [2] 89 27 [2] a7 05 [2] b3 1e [2] bc 04 [2] a2 19 [2] a0 18 [2] bb 1e [2] a7 19 [2] bb 36 }

  condition:
    any of them
}