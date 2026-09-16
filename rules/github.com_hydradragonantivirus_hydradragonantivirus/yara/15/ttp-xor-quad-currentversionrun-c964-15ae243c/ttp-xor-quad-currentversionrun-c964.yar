rule TTP_XOR_QUAD_CurrentVersionRun_c964 {
  strings:
    $key_c964 = { 9a 0b [2] be 05 [2] 95 29 [2] bb 0b [2] af 10 [2] a0 0a [2] be 17 [2] bc 16 [2] a7 10 [2] bb 17 [2] a7 38 }

  condition:
    any of them
}