rule TTP_XOR_QUAD_CurrentVersionRun_d549 {
  strings:
    $key_d549 = { 86 26 [2] a2 28 [2] 89 04 [2] a7 26 [2] b3 3d [2] bc 27 [2] a2 3a [2] a0 3b [2] bb 3d [2] a7 3a [2] bb 15 }

  condition:
    any of them
}