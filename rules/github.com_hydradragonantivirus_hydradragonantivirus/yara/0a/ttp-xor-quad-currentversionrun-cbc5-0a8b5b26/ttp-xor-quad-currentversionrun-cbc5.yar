rule TTP_XOR_QUAD_CurrentVersionRun_cbc5 {
  strings:
    $key_cbc5 = { 98 aa [2] bc a4 [2] 97 88 [2] b9 aa [2] ad b1 [2] a2 ab [2] bc b6 [2] be b7 [2] a5 b1 [2] b9 b6 [2] a5 99 }

  condition:
    any of them
}