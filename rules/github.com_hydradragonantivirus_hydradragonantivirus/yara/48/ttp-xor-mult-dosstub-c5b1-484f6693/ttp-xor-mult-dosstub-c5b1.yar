rule TTP_XOR_MULT_DOSStub_c5b1 {
  strings:
    $key_c5b1 = { 91 d9 [2] e5 c1 [2] a2 c3 [2] e5 d2 [2] ab de [2] a7 d4 [2] b0 df [2] ab 91 [2] 96 }

  condition:
    any of them
}