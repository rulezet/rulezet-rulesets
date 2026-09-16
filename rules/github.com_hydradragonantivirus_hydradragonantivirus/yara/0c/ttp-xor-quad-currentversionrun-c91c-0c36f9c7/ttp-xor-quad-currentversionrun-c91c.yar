rule TTP_XOR_QUAD_CurrentVersionRun_c91c {
  strings:
    $key_c91c = { 9a 73 [2] be 7d [2] 95 51 [2] bb 73 [2] af 68 [2] a0 72 [2] be 6f [2] bc 6e [2] a7 68 [2] bb 6f [2] a7 40 }

  condition:
    any of them
}