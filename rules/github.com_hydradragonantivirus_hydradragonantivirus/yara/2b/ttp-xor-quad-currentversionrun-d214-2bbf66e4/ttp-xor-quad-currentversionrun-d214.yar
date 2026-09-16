rule TTP_XOR_QUAD_CurrentVersionRun_d214 {
  strings:
    $key_d214 = { 81 7b [2] a5 75 [2] 8e 59 [2] a0 7b [2] b4 60 [2] bb 7a [2] a5 67 [2] a7 66 [2] bc 60 [2] a0 67 [2] bc 48 }

  condition:
    any of them
}