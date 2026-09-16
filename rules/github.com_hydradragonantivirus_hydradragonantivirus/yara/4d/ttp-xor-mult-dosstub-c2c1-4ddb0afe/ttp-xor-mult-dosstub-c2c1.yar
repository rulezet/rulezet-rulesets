rule TTP_XOR_MULT_DOSStub_c2c1 {
  strings:
    $key_c2c1 = { 96 a9 [2] e2 b1 [2] a5 b3 [2] e2 a2 [2] ac ae [2] a0 a4 [2] b7 af [2] ac e1 [2] 91 }

  condition:
    any of them
}