rule TTP_XOR_QUAD_CurrentVersionRun_d2f2 {
  strings:
    $key_d2f2 = { 81 9d [2] a5 93 [2] 8e bf [2] a0 9d [2] b4 86 [2] bb 9c [2] a5 81 [2] a7 80 [2] bc 86 [2] a0 81 [2] bc ae }

  condition:
    any of them
}