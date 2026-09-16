rule TTP_XOR_QUAD_CurrentVersionRun_c965 {
  strings:
    $key_c965 = { 9a 0a [2] be 04 [2] 95 28 [2] bb 0a [2] af 11 [2] a0 0b [2] be 16 [2] bc 17 [2] a7 11 [2] bb 16 [2] a7 39 }

  condition:
    any of them
}