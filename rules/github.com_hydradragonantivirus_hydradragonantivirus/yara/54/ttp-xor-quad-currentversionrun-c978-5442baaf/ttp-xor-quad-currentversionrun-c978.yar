rule TTP_XOR_QUAD_CurrentVersionRun_c978 {
  strings:
    $key_c978 = { 9a 17 [2] be 19 [2] 95 35 [2] bb 17 [2] af 0c [2] a0 16 [2] be 0b [2] bc 0a [2] a7 0c [2] bb 0b [2] a7 24 }

  condition:
    any of them
}