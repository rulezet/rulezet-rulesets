rule TTP_XOR_QUAD_CurrentVersionRun_da60 {
  strings:
    $key_da60 = { 89 0f [2] ad 01 [2] 86 2d [2] a8 0f [2] bc 14 [2] b3 0e [2] ad 13 [2] af 12 [2] b4 14 [2] a8 13 [2] b4 3c }

  condition:
    any of them
}