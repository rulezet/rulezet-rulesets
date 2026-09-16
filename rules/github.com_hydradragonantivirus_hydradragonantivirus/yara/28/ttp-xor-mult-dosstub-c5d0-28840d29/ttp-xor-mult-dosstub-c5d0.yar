rule TTP_XOR_MULT_DOSStub_c5d0 {
  strings:
    $key_c5d0 = { 91 b8 [2] e5 a0 [2] a2 a2 [2] e5 b3 [2] ab bf [2] a7 b5 [2] b0 be [2] ab f0 [2] 96 }

  condition:
    any of them
}