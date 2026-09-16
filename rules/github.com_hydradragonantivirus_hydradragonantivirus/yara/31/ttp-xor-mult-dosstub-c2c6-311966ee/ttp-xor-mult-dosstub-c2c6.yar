rule TTP_XOR_MULT_DOSStub_c2c6 {
  strings:
    $key_c2c6 = { 96 ae [2] e2 b6 [2] a5 b4 [2] e2 a5 [2] ac a9 [2] a0 a3 [2] b7 a8 [2] ac e6 [2] 91 }

  condition:
    any of them
}