rule TTP_XOR_MULT_DOSStub_c596 {
  strings:
    $key_c596 = { 91 fe [2] e5 e6 [2] a2 e4 [2] e5 f5 [2] ab f9 [2] a7 f3 [2] b0 f8 [2] ab b6 [2] 96 }

  condition:
    any of them
}