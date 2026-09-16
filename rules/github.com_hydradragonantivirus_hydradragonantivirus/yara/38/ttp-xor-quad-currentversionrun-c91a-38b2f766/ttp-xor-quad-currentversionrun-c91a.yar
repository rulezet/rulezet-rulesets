rule TTP_XOR_QUAD_CurrentVersionRun_c91a {
  strings:
    $key_c91a = { 9a 75 [2] be 7b [2] 95 57 [2] bb 75 [2] af 6e [2] a0 74 [2] be 69 [2] bc 68 [2] a7 6e [2] bb 69 [2] a7 46 }

  condition:
    any of them
}