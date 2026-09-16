rule TTP_XOR_QUAD_CurrentVersionRun_d209 {
  strings:
    $key_d209 = { 81 66 [2] a5 68 [2] 8e 44 [2] a0 66 [2] b4 7d [2] bb 67 [2] a5 7a [2] a7 7b [2] bc 7d [2] a0 7a [2] bc 55 }

  condition:
    any of them
}