rule TTP_XOR_QUAD_CurrentVersionRun_da5e {
  strings:
    $key_da5e = { 89 31 [2] ad 3f [2] 86 13 [2] a8 31 [2] bc 2a [2] b3 30 [2] ad 2d [2] af 2c [2] b4 2a [2] a8 2d [2] b4 02 }

  condition:
    any of them
}