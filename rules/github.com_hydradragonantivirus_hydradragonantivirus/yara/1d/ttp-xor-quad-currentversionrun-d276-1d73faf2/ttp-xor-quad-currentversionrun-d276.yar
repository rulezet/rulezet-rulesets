rule TTP_XOR_QUAD_CurrentVersionRun_d276 {
  strings:
    $key_d276 = { 81 19 [2] a5 17 [2] 8e 3b [2] a0 19 [2] b4 02 [2] bb 18 [2] a5 05 [2] a7 04 [2] bc 02 [2] a0 05 [2] bc 2a }

  condition:
    any of them
}