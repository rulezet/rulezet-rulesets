rule TTP_XOR_QUAD_CurrentVersionRun_d54b {
  strings:
    $key_d54b = { 86 24 [2] a2 2a [2] 89 06 [2] a7 24 [2] b3 3f [2] bc 25 [2] a2 38 [2] a0 39 [2] bb 3f [2] a7 38 [2] bb 17 }

  condition:
    any of them
}