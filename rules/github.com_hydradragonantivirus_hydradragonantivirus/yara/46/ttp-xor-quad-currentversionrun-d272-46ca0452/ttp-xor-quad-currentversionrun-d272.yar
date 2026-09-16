rule TTP_XOR_QUAD_CurrentVersionRun_d272 {
  strings:
    $key_d272 = { 81 1d [2] a5 13 [2] 8e 3f [2] a0 1d [2] b4 06 [2] bb 1c [2] a5 01 [2] a7 00 [2] bc 06 [2] a0 01 [2] bc 2e }

  condition:
    any of them
}