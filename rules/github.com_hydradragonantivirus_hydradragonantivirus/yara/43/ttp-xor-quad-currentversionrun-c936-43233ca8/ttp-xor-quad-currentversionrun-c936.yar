rule TTP_XOR_QUAD_CurrentVersionRun_c936 {
  strings:
    $key_c936 = { 9a 59 [2] be 57 [2] 95 7b [2] bb 59 [2] af 42 [2] a0 58 [2] be 45 [2] bc 44 [2] a7 42 [2] bb 45 [2] a7 6a }

  condition:
    any of them
}