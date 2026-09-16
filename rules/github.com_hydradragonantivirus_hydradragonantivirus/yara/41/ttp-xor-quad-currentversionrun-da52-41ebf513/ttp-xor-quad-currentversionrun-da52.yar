rule TTP_XOR_QUAD_CurrentVersionRun_da52 {
  strings:
    $key_da52 = { 89 3d [2] ad 33 [2] 86 1f [2] a8 3d [2] bc 26 [2] b3 3c [2] ad 21 [2] af 20 [2] b4 26 [2] a8 21 [2] b4 0e }

  condition:
    any of them
}