rule TTP_XOR_QUAD_CurrentVersionRun_c93a {
  strings:
    $key_c93a = { 9a 55 [2] be 5b [2] 95 77 [2] bb 55 [2] af 4e [2] a0 54 [2] be 49 [2] bc 48 [2] a7 4e [2] bb 49 [2] a7 66 }

  condition:
    any of them
}