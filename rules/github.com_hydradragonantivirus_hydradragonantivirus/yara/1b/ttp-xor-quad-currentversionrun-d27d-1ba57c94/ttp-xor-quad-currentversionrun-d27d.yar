rule TTP_XOR_QUAD_CurrentVersionRun_d27d {
  strings:
    $key_d27d = { 81 12 [2] a5 1c [2] 8e 30 [2] a0 12 [2] b4 09 [2] bb 13 [2] a5 0e [2] a7 0f [2] bc 09 [2] a0 0e [2] bc 21 }

  condition:
    any of them
}