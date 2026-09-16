rule TTP_XOR_QUAD_CurrentVersionRun_d266 {
  strings:
    $key_d266 = { 81 09 [2] a5 07 [2] 8e 2b [2] a0 09 [2] b4 12 [2] bb 08 [2] a5 15 [2] a7 14 [2] bc 12 [2] a0 15 [2] bc 3a }

  condition:
    any of them
}