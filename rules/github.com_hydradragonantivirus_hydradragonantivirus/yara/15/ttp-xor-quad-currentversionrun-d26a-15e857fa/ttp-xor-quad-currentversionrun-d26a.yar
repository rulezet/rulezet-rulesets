rule TTP_XOR_QUAD_CurrentVersionRun_d26a {
  strings:
    $key_d26a = { 81 05 [2] a5 0b [2] 8e 27 [2] a0 05 [2] b4 1e [2] bb 04 [2] a5 19 [2] a7 18 [2] bc 1e [2] a0 19 [2] bc 36 }

  condition:
    any of them
}