rule TTP_XOR_MULT_DOSStub_c5d2 {
  strings:
    $key_c5d2 = { 91 ba [2] e5 a2 [2] a2 a0 [2] e5 b1 [2] ab bd [2] a7 b7 [2] b0 bc [2] ab f2 [2] 96 }

  condition:
    any of them
}