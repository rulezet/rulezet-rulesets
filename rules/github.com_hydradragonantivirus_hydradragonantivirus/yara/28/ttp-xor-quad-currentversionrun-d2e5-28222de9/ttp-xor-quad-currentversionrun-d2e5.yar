rule TTP_XOR_QUAD_CurrentVersionRun_d2e5 {
  strings:
    $key_d2e5 = { 81 8a [2] a5 84 [2] 8e a8 [2] a0 8a [2] b4 91 [2] bb 8b [2] a5 96 [2] a7 97 [2] bc 91 [2] a0 96 [2] bc b9 }

  condition:
    any of them
}