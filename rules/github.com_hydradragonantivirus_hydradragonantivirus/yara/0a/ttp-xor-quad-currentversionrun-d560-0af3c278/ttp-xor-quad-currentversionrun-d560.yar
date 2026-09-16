rule TTP_XOR_QUAD_CurrentVersionRun_d560 {
  strings:
    $key_d560 = { 86 0f [2] a2 01 [2] 89 2d [2] a7 0f [2] b3 14 [2] bc 0e [2] a2 13 [2] a0 12 [2] bb 14 [2] a7 13 [2] bb 3c }

  condition:
    any of them
}