rule TTP_XOR_QUAD_CurrentVersionRun_c90b {
  strings:
    $key_c90b = { 9a 64 [2] be 6a [2] 95 46 [2] bb 64 [2] af 7f [2] a0 65 [2] be 78 [2] bc 79 [2] a7 7f [2] bb 78 [2] a7 57 }

  condition:
    any of them
}