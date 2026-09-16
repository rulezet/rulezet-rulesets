rule TTP_XOR_QUAD_CurrentVersionRun_d265 {
  strings:
    $key_d265 = { 81 0a [2] a5 04 [2] 8e 28 [2] a0 0a [2] b4 11 [2] bb 0b [2] a5 16 [2] a7 17 [2] bc 11 [2] a0 16 [2] bc 39 }

  condition:
    any of them
}