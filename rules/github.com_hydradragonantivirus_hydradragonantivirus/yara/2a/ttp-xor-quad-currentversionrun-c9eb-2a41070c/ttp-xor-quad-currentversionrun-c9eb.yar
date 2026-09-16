rule TTP_XOR_QUAD_CurrentVersionRun_c9eb {
  strings:
    $key_c9eb = { 9a 84 [2] be 8a [2] 95 a6 [2] bb 84 [2] af 9f [2] a0 85 [2] be 98 [2] bc 99 [2] a7 9f [2] bb 98 [2] a7 b7 }

  condition:
    any of them
}