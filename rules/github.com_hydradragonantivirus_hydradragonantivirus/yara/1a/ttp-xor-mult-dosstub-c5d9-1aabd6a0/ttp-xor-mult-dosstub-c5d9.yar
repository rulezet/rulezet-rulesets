rule TTP_XOR_MULT_DOSStub_c5d9 {
  strings:
    $key_c5d9 = { 91 b1 [2] e5 a9 [2] a2 ab [2] e5 ba [2] ab b6 [2] a7 bc [2] b0 b7 [2] ab f9 [2] 96 }

  condition:
    any of them
}