rule TTP_XOR_QUAD_CurrentVersionRun_d5f8 {
  strings:
    $key_d5f8 = { 86 97 [2] a2 99 [2] 89 b5 [2] a7 97 [2] b3 8c [2] bc 96 [2] a2 8b [2] a0 8a [2] bb 8c [2] a7 8b [2] bb a4 }

  condition:
    any of them
}