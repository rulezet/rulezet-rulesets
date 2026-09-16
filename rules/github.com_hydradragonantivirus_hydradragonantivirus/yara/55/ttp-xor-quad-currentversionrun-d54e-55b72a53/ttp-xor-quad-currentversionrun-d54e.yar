rule TTP_XOR_QUAD_CurrentVersionRun_d54e {
  strings:
    $key_d54e = { 86 21 [2] a2 2f [2] 89 03 [2] a7 21 [2] b3 3a [2] bc 20 [2] a2 3d [2] a0 3c [2] bb 3a [2] a7 3d [2] bb 12 }

  condition:
    any of them
}