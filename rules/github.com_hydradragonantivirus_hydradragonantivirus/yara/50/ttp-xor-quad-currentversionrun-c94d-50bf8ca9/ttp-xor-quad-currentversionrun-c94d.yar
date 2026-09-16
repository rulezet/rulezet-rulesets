rule TTP_XOR_QUAD_CurrentVersionRun_c94d {
  strings:
    $key_c94d = { 9a 22 [2] be 2c [2] 95 00 [2] bb 22 [2] af 39 [2] a0 23 [2] be 3e [2] bc 3f [2] a7 39 [2] bb 3e [2] a7 11 }

  condition:
    any of them
}