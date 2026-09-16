rule TTP_XOR_QUAD_CurrentVersionRun_c9fb {
  strings:
    $key_c9fb = { 9a 94 [2] be 9a [2] 95 b6 [2] bb 94 [2] af 8f [2] a0 95 [2] be 88 [2] bc 89 [2] a7 8f [2] bb 88 [2] a7 a7 }

  condition:
    any of them
}