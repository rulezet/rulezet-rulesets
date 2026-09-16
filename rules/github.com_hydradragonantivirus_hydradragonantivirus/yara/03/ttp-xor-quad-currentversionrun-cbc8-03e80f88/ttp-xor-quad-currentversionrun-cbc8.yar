rule TTP_XOR_QUAD_CurrentVersionRun_cbc8 {
  strings:
    $key_cbc8 = { 98 a7 [2] bc a9 [2] 97 85 [2] b9 a7 [2] ad bc [2] a2 a6 [2] bc bb [2] be ba [2] a5 bc [2] b9 bb [2] a5 94 }

  condition:
    any of them
}