rule TTP_XOR_QUAD_CurrentVersionRun_d23e {
  strings:
    $key_d23e = { 81 51 [2] a5 5f [2] 8e 73 [2] a0 51 [2] b4 4a [2] bb 50 [2] a5 4d [2] a7 4c [2] bc 4a [2] a0 4d [2] bc 62 }

  condition:
    any of them
}