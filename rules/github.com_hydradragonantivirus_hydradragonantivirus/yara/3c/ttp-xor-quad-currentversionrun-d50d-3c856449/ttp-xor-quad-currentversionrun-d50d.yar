rule TTP_XOR_QUAD_CurrentVersionRun_d50d {
  strings:
    $key_d50d = { 86 62 [2] a2 6c [2] 89 40 [2] a7 62 [2] b3 79 [2] bc 63 [2] a2 7e [2] a0 7f [2] bb 79 [2] a7 7e [2] bb 51 }

  condition:
    any of them
}