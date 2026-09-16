rule TTP_XOR_QUAD_CurrentVersionRun_d2eb {
  strings:
    $key_d2eb = { 81 84 [2] a5 8a [2] 8e a6 [2] a0 84 [2] b4 9f [2] bb 85 [2] a5 98 [2] a7 99 [2] bc 9f [2] a0 98 [2] bc b7 }

  condition:
    any of them
}