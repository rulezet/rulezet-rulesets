rule TTP_XOR_QUAD_CurrentVersionRun_c904 {
  strings:
    $key_c904 = { 9a 6b [2] be 65 [2] 95 49 [2] bb 6b [2] af 70 [2] a0 6a [2] be 77 [2] bc 76 [2] a7 70 [2] bb 77 [2] a7 58 }

  condition:
    any of them
}