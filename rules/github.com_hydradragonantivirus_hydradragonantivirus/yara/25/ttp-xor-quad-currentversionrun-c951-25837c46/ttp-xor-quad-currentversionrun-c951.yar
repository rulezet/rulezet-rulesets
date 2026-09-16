rule TTP_XOR_QUAD_CurrentVersionRun_c951 {
  strings:
    $key_c951 = { 9a 3e [2] be 30 [2] 95 1c [2] bb 3e [2] af 25 [2] a0 3f [2] be 22 [2] bc 23 [2] a7 25 [2] bb 22 [2] a7 0d }

  condition:
    any of them
}