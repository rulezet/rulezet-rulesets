rule TTP_XOR_QUAD_CurrentVersionRun_ceee {
  strings:
    $key_ceee = { 9d 81 [2] b9 8f [2] 92 a3 [2] bc 81 [2] a8 9a [2] a7 80 [2] b9 9d [2] bb 9c [2] a0 9a [2] bc 9d [2] a0 b2 }

  condition:
    any of them
}