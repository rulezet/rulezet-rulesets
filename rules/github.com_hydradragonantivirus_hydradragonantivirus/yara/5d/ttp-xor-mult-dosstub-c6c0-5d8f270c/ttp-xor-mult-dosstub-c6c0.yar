rule TTP_XOR_MULT_DOSStub_c6c0 {
  strings:
    $key_c6c0 = { 92 a8 [2] e6 b0 [2] a1 b2 [2] e6 a3 [2] a8 af [2] a4 a5 [2] b3 ae [2] a8 e0 [2] 95 }

  condition:
    any of them
}