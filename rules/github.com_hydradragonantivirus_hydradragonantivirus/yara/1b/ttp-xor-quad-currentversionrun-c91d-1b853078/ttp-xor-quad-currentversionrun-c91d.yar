rule TTP_XOR_QUAD_CurrentVersionRun_c91d {
  strings:
    $key_c91d = { 9a 72 [2] be 7c [2] 95 50 [2] bb 72 [2] af 69 [2] a0 73 [2] be 6e [2] bc 6f [2] a7 69 [2] bb 6e [2] a7 41 }

  condition:
    any of them
}