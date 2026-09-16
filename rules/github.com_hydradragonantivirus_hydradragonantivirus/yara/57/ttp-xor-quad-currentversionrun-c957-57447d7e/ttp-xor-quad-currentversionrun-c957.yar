rule TTP_XOR_QUAD_CurrentVersionRun_c957 {
  strings:
    $key_c957 = { 9a 38 [2] be 36 [2] 95 1a [2] bb 38 [2] af 23 [2] a0 39 [2] be 24 [2] bc 25 [2] a7 23 [2] bb 24 [2] a7 0b }

  condition:
    any of them
}