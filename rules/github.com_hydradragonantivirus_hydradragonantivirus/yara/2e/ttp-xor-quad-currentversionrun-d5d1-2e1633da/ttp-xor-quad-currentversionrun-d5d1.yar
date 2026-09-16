rule TTP_XOR_QUAD_CurrentVersionRun_d5d1 {
  strings:
    $key_d5d1 = { 86 be [2] a2 b0 [2] 89 9c [2] a7 be [2] b3 a5 [2] bc bf [2] a2 a2 [2] a0 a3 [2] bb a5 [2] a7 a2 [2] bb 8d }

  condition:
    any of them
}