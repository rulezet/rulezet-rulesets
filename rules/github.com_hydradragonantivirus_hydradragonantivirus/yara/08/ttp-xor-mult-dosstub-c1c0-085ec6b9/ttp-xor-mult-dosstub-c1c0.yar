rule TTP_XOR_MULT_DOSStub_c1c0 {
  strings:
    $key_c1c0 = { 95 a8 [2] e1 b0 [2] a6 b2 [2] e1 a3 [2] af af [2] a3 a5 [2] b4 ae [2] af e0 [2] 92 }

  condition:
    any of them
}