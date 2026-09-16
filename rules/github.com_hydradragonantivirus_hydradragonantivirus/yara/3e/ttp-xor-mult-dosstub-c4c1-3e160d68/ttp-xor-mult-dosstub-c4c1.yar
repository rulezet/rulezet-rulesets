rule TTP_XOR_MULT_DOSStub_c4c1 {
  strings:
    $key_c4c1 = { 90 a9 [2] e4 b1 [2] a3 b3 [2] e4 a2 [2] aa ae [2] a6 a4 [2] b1 af [2] aa e1 [2] 97 }

  condition:
    any of them
}