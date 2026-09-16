rule TTP_XOR_QUAD_CurrentVersionRun_cbc1 {
  strings:
    $key_cbc1 = { 98 ae [2] bc a0 [2] 97 8c [2] b9 ae [2] ad b5 [2] a2 af [2] bc b2 [2] be b3 [2] a5 b5 [2] b9 b2 [2] a5 9d }

  condition:
    any of them
}