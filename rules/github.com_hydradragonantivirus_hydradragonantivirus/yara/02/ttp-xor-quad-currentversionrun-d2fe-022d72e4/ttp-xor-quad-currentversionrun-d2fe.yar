rule TTP_XOR_QUAD_CurrentVersionRun_d2fe {
  strings:
    $key_d2fe = { 81 91 [2] a5 9f [2] 8e b3 [2] a0 91 [2] b4 8a [2] bb 90 [2] a5 8d [2] a7 8c [2] bc 8a [2] a0 8d [2] bc a2 }

  condition:
    any of them
}