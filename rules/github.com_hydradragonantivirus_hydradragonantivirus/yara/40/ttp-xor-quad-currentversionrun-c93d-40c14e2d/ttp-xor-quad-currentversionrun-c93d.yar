rule TTP_XOR_QUAD_CurrentVersionRun_c93d {
  strings:
    $key_c93d = { 9a 52 [2] be 5c [2] 95 70 [2] bb 52 [2] af 49 [2] a0 53 [2] be 4e [2] bc 4f [2] a7 49 [2] bb 4e [2] a7 61 }

  condition:
    any of them
}