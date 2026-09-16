rule TTP_XOR_QUAD_CurrentVersionRun_cbc3 {
  strings:
    $key_cbc3 = { 98 ac [2] bc a2 [2] 97 8e [2] b9 ac [2] ad b7 [2] a2 ad [2] bc b0 [2] be b1 [2] a5 b7 [2] b9 b0 [2] a5 9f }

  condition:
    any of them
}