rule TTP_XOR_QUAD_CurrentVersionRun_c95e {
  strings:
    $key_c95e = { 9a 31 [2] be 3f [2] 95 13 [2] bb 31 [2] af 2a [2] a0 30 [2] be 2d [2] bc 2c [2] a7 2a [2] bb 2d [2] a7 02 }

  condition:
    any of them
}