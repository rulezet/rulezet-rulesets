rule TTP_XOR_QUAD_CurrentVersionRun_c927 {
  strings:
    $key_c927 = { 9a 48 [2] be 46 [2] 95 6a [2] bb 48 [2] af 53 [2] a0 49 [2] be 54 [2] bc 55 [2] a7 53 [2] bb 54 [2] a7 7b }

  condition:
    any of them
}