rule TTP_XOR_MULT_DOSStub_c2c7 {
  strings:
    $key_c2c7 = { 96 af [2] e2 b7 [2] a5 b5 [2] e2 a4 [2] ac a8 [2] a0 a2 [2] b7 a9 [2] ac e7 [2] 91 }

  condition:
    any of them
}