rule TTP_XOR_MULT_DOSStub_c2c8 {
  strings:
    $key_c2c8 = { 96 a0 [2] e2 b8 [2] a5 ba [2] e2 ab [2] ac a7 [2] a0 ad [2] b7 a6 [2] ac e8 [2] 91 }

  condition:
    any of them
}