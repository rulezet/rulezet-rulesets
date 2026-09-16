rule TTP_XOR_QUAD_CurrentVersionRun_cbc7 {
  strings:
    $key_cbc7 = { 98 a8 [2] bc a6 [2] 97 8a [2] b9 a8 [2] ad b3 [2] a2 a9 [2] bc b4 [2] be b5 [2] a5 b3 [2] b9 b4 [2] a5 9b }

  condition:
    any of them
}