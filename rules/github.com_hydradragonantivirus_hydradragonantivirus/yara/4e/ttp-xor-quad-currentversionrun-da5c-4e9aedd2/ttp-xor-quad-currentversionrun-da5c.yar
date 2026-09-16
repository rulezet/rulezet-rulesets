rule TTP_XOR_QUAD_CurrentVersionRun_da5c {
  strings:
    $key_da5c = { 89 33 [2] ad 3d [2] 86 11 [2] a8 33 [2] bc 28 [2] b3 32 [2] ad 2f [2] af 2e [2] b4 28 [2] a8 2f [2] b4 00 }

  condition:
    any of them
}