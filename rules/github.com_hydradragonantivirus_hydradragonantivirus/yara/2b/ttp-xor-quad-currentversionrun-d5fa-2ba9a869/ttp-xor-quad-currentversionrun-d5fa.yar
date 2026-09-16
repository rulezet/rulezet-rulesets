rule TTP_XOR_QUAD_CurrentVersionRun_d5fa {
  strings:
    $key_d5fa = { 86 95 [2] a2 9b [2] 89 b7 [2] a7 95 [2] b3 8e [2] bc 94 [2] a2 89 [2] a0 88 [2] bb 8e [2] a7 89 [2] bb a6 }

  condition:
    any of them
}