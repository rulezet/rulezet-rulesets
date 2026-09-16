rule TTP_XOR_QUAD_CurrentVersionRun_d54d {
  strings:
    $key_d54d = { 86 22 [2] a2 2c [2] 89 00 [2] a7 22 [2] b3 39 [2] bc 23 [2] a2 3e [2] a0 3f [2] bb 39 [2] a7 3e [2] bb 11 }

  condition:
    any of them
}