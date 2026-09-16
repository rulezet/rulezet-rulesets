rule TTP_XOR_MULT_DOSStub_c0c1 {
  strings:
    $key_c0c1 = { 94 a9 [2] e0 b1 [2] a7 b3 [2] e0 a2 [2] ae ae [2] a2 a4 [2] b5 af [2] ae e1 [2] 93 }

  condition:
    any of them
}