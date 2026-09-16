rule TTP_XOR_QUAD_CurrentVersionRun_c9f9 {
  strings:
    $key_c9f9 = { 9a 96 [2] be 98 [2] 95 b4 [2] bb 96 [2] af 8d [2] a0 97 [2] be 8a [2] bc 8b [2] a7 8d [2] bb 8a [2] a7 a5 }

  condition:
    any of them
}