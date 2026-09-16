rule TTP_XOR_MULT_DOSStub_c3d0 {
  strings:
    $key_c3d0 = { 97 b8 [2] e3 a0 [2] a4 a2 [2] e3 b3 [2] ad bf [2] a1 b5 [2] b6 be [2] ad f0 [2] 90 }

  condition:
    any of them
}