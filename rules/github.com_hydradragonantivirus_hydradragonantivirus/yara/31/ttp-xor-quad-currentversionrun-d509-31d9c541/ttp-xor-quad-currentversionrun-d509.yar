rule TTP_XOR_QUAD_CurrentVersionRun_d509 {
  strings:
    $key_d509 = { 86 66 [2] a2 68 [2] 89 44 [2] a7 66 [2] b3 7d [2] bc 67 [2] a2 7a [2] a0 7b [2] bb 7d [2] a7 7a [2] bb 55 }

  condition:
    any of them
}