rule TTP_XOR_QUAD_CurrentVersionRun_d5b3 {
  strings:
    $key_d5b3 = { 86 dc [2] a2 d2 [2] 89 fe [2] a7 dc [2] b3 c7 [2] bc dd [2] a2 c0 [2] a0 c1 [2] bb c7 [2] a7 c0 [2] bb ef }

  condition:
    any of them
}