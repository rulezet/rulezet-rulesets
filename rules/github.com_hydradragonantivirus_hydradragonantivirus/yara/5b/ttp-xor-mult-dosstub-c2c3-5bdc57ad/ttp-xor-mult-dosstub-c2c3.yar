rule TTP_XOR_MULT_DOSStub_c2c3 {
  strings:
    $key_c2c3 = { 96 ab [2] e2 b3 [2] a5 b1 [2] e2 a0 [2] ac ac [2] a0 a6 [2] b7 ad [2] ac e3 [2] 91 }

  condition:
    any of them
}