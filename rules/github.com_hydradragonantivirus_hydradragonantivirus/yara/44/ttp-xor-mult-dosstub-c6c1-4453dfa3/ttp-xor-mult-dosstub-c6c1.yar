rule TTP_XOR_MULT_DOSStub_c6c1 {
  strings:
    $key_c6c1 = { 92 a9 [2] e6 b1 [2] a1 b3 [2] e6 a2 [2] a8 ae [2] a4 a4 [2] b3 af [2] a8 e1 [2] 95 }

  condition:
    any of them
}