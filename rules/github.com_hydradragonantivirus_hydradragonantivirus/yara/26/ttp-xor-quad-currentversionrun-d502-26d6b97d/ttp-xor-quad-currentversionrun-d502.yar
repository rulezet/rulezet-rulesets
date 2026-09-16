rule TTP_XOR_QUAD_CurrentVersionRun_d502 {
  strings:
    $key_d502 = { 86 6d [2] a2 63 [2] 89 4f [2] a7 6d [2] b3 76 [2] bc 6c [2] a2 71 [2] a0 70 [2] bb 76 [2] a7 71 [2] bb 5e }

  condition:
    any of them
}