rule TTP_XOR_QUAD_CurrentVersionRun_ceea {
  strings:
    $key_ceea = { 9d 85 [2] b9 8b [2] 92 a7 [2] bc 85 [2] a8 9e [2] a7 84 [2] b9 99 [2] bb 98 [2] a0 9e [2] bc 99 [2] a0 b6 }

  condition:
    any of them
}