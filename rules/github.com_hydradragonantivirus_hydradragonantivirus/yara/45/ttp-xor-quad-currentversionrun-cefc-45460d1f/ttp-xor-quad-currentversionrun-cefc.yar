rule TTP_XOR_QUAD_CurrentVersionRun_cefc {
  strings:
    $key_cefc = { 9d 93 [2] b9 9d [2] 92 b1 [2] bc 93 [2] a8 88 [2] a7 92 [2] b9 8f [2] bb 8e [2] a0 88 [2] bc 8f [2] a0 a0 }

  condition:
    any of them
}