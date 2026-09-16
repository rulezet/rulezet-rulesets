rule TTP_XOR_QUAD_CurrentVersionRun_c907 {
  strings:
    $key_c907 = { 9a 68 [2] be 66 [2] 95 4a [2] bb 68 [2] af 73 [2] a0 69 [2] be 74 [2] bc 75 [2] a7 73 [2] bb 74 [2] a7 5b }

  condition:
    any of them
}