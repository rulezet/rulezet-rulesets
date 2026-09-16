rule TTP_XOR_QUAD_CurrentVersionRun_d240 {
  strings:
    $key_d240 = { 81 2f [2] a5 21 [2] 8e 0d [2] a0 2f [2] b4 34 [2] bb 2e [2] a5 33 [2] a7 32 [2] bc 34 [2] a0 33 [2] bc 1c }

  condition:
    any of them
}