rule TTP_XOR_MULT_DOSStub_d090 {
  strings:
    $key_d090 = { 84 f8 [2] f0 e0 [2] b7 e2 [2] f0 f3 [2] be ff [2] b2 f5 [2] a5 fe [2] be b0 [2] 83 }

  condition:
    any of them
}