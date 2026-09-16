rule TTP_XOR_QUAD_CurrentVersionRun_d26e {
  strings:
    $key_d26e = { 81 01 [2] a5 0f [2] 8e 23 [2] a0 01 [2] b4 1a [2] bb 00 [2] a5 1d [2] a7 1c [2] bc 1a [2] a0 1d [2] bc 32 }

  condition:
    any of them
}