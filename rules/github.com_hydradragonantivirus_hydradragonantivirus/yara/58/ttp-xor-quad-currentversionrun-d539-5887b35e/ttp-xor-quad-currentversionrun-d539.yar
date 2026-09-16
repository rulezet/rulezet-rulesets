rule TTP_XOR_QUAD_CurrentVersionRun_d539 {
  strings:
    $key_d539 = { 86 56 [2] a2 58 [2] 89 74 [2] a7 56 [2] b3 4d [2] bc 57 [2] a2 4a [2] a0 4b [2] bb 4d [2] a7 4a [2] bb 65 }

  condition:
    any of them
}