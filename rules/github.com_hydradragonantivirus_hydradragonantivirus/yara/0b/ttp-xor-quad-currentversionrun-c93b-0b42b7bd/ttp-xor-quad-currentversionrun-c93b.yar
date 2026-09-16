rule TTP_XOR_QUAD_CurrentVersionRun_c93b {
  strings:
    $key_c93b = { 9a 54 [2] be 5a [2] 95 76 [2] bb 54 [2] af 4f [2] a0 55 [2] be 48 [2] bc 49 [2] a7 4f [2] bb 48 [2] a7 67 }

  condition:
    any of them
}