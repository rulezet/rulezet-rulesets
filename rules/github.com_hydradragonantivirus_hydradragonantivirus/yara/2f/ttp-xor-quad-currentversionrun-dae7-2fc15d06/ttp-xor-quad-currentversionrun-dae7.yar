rule TTP_XOR_QUAD_CurrentVersionRun_dae7 {
  strings:
    $key_dae7 = { 89 88 [2] ad 86 [2] 86 aa [2] a8 88 [2] bc 93 [2] b3 89 [2] ad 94 [2] af 95 [2] b4 93 [2] a8 94 [2] b4 bb }

  condition:
    any of them
}