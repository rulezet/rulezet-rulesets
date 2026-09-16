rule TTP_XOR_QUAD_CurrentVersionRun_c9e1 {
  strings:
    $key_c9e1 = { 9a 8e [2] be 80 [2] 95 ac [2] bb 8e [2] af 95 [2] a0 8f [2] be 92 [2] bc 93 [2] a7 95 [2] bb 92 [2] a7 bd }

  condition:
    any of them
}