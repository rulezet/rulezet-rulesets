rule TTP_XOR_QUAD_CurrentVersionRun_d5e9 {
  strings:
    $key_d5e9 = { 86 86 [2] a2 88 [2] 89 a4 [2] a7 86 [2] b3 9d [2] bc 87 [2] a2 9a [2] a0 9b [2] bb 9d [2] a7 9a [2] bb b5 }

  condition:
    any of them
}