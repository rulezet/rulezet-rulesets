rule TTP_XOR_QUAD_CurrentVersionRun_c9f0 {
  strings:
    $key_c9f0 = { 9a 9f [2] be 91 [2] 95 bd [2] bb 9f [2] af 84 [2] a0 9e [2] be 83 [2] bc 82 [2] a7 84 [2] bb 83 [2] a7 ac }

  condition:
    any of them
}