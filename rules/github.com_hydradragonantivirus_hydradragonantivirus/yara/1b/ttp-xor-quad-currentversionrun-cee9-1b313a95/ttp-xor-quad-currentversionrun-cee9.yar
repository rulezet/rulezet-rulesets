rule TTP_XOR_QUAD_CurrentVersionRun_cee9 {
  strings:
    $key_cee9 = { 9d 86 [2] b9 88 [2] 92 a4 [2] bc 86 [2] a8 9d [2] a7 87 [2] b9 9a [2] bb 9b [2] a0 9d [2] bc 9a [2] a0 b5 }

  condition:
    any of them
}