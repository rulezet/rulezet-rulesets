rule TTP_XOR_QUAD_CurrentVersionRun_d27e {
  strings:
    $key_d27e = { 81 11 [2] a5 1f [2] 8e 33 [2] a0 11 [2] b4 0a [2] bb 10 [2] a5 0d [2] a7 0c [2] bc 0a [2] a0 0d [2] bc 22 }

  condition:
    any of them
}