rule TTP_XOR_QUAD_CurrentVersionRun_c95b {
  strings:
    $key_c95b = { 9a 34 [2] be 3a [2] 95 16 [2] bb 34 [2] af 2f [2] a0 35 [2] be 28 [2] bc 29 [2] a7 2f [2] bb 28 [2] a7 07 }

  condition:
    any of them
}