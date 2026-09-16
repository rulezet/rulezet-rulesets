rule TTP_XOR_QUAD_CurrentVersionRun_d57b {
  strings:
    $key_d57b = { 86 14 [2] a2 1a [2] 89 36 [2] a7 14 [2] b3 0f [2] bc 15 [2] a2 08 [2] a0 09 [2] bb 0f [2] a7 08 [2] bb 27 }

  condition:
    any of them
}