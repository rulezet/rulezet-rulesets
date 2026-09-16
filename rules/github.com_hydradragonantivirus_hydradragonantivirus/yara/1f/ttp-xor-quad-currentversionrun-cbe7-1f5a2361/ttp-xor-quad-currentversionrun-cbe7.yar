rule TTP_XOR_QUAD_CurrentVersionRun_cbe7 {
  strings:
    $key_cbe7 = { 98 88 [2] bc 86 [2] 97 aa [2] b9 88 [2] ad 93 [2] a2 89 [2] bc 94 [2] be 95 [2] a5 93 [2] b9 94 [2] a5 bb }

  condition:
    any of them
}