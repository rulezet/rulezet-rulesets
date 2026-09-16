rule TTP_XOR_QUAD_CurrentVersionRun_dad5 {
  strings:
    $key_dad5 = { 89 ba [2] ad b4 [2] 86 98 [2] a8 ba [2] bc a1 [2] b3 bb [2] ad a6 [2] af a7 [2] b4 a1 [2] a8 a6 [2] b4 89 }

  condition:
    any of them
}