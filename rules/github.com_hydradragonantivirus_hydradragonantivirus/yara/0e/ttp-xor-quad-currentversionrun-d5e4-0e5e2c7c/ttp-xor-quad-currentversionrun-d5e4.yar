rule TTP_XOR_QUAD_CurrentVersionRun_d5e4 {
  strings:
    $key_d5e4 = { 86 8b [2] a2 85 [2] 89 a9 [2] a7 8b [2] b3 90 [2] bc 8a [2] a2 97 [2] a0 96 [2] bb 90 [2] a7 97 [2] bb b8 }

  condition:
    any of them
}