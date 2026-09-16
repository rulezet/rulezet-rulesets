rule TTP_XOR_QUAD_CurrentVersionRun_c91b {
  strings:
    $key_c91b = { 9a 74 [2] be 7a [2] 95 56 [2] bb 74 [2] af 6f [2] a0 75 [2] be 68 [2] bc 69 [2] a7 6f [2] bb 68 [2] a7 47 }

  condition:
    any of them
}