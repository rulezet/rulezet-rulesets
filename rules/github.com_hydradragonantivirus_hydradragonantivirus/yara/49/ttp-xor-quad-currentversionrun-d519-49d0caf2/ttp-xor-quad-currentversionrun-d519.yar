rule TTP_XOR_QUAD_CurrentVersionRun_d519 {
  strings:
    $key_d519 = { 86 76 [2] a2 78 [2] 89 54 [2] a7 76 [2] b3 6d [2] bc 77 [2] a2 6a [2] a0 6b [2] bb 6d [2] a7 6a [2] bb 45 }

  condition:
    any of them
}