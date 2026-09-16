rule TTP_XOR_QUAD_CurrentVersionRun_c97a {
  strings:
    $key_c97a = { 9a 15 [2] be 1b [2] 95 37 [2] bb 15 [2] af 0e [2] a0 14 [2] be 09 [2] bc 08 [2] a7 0e [2] bb 09 [2] a7 26 }

  condition:
    any of them
}