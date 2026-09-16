rule TTP_XOR_QUAD_CurrentVersionRun_c97d {
  strings:
    $key_c97d = { 9a 12 [2] be 1c [2] 95 30 [2] bb 12 [2] af 09 [2] a0 13 [2] be 0e [2] bc 0f [2] a7 09 [2] bb 0e [2] a7 21 }

  condition:
    any of them
}