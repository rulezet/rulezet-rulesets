rule TTP_XOR_QUAD_CurrentVersionRun_cbc2 {
  strings:
    $key_cbc2 = { 98 ad [2] bc a3 [2] 97 8f [2] b9 ad [2] ad b6 [2] a2 ac [2] bc b1 [2] be b0 [2] a5 b6 [2] b9 b1 [2] a5 9e }

  condition:
    any of them
}