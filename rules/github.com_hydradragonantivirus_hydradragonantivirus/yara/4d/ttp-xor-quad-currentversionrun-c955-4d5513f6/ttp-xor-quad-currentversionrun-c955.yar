rule TTP_XOR_QUAD_CurrentVersionRun_c955 {
  strings:
    $key_c955 = { 9a 3a [2] be 34 [2] 95 18 [2] bb 3a [2] af 21 [2] a0 3b [2] be 26 [2] bc 27 [2] a7 21 [2] bb 26 [2] a7 09 }

  condition:
    any of them
}