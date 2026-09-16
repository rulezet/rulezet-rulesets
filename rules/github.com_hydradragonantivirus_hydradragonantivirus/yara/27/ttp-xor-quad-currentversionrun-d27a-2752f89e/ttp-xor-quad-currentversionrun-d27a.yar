rule TTP_XOR_QUAD_CurrentVersionRun_d27a {
  strings:
    $key_d27a = { 81 15 [2] a5 1b [2] 8e 37 [2] a0 15 [2] b4 0e [2] bb 14 [2] a5 09 [2] a7 08 [2] bc 0e [2] a0 09 [2] bc 26 }

  condition:
    any of them
}