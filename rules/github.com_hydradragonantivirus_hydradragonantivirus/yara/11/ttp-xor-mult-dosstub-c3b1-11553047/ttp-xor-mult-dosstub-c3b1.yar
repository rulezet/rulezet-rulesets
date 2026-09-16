rule TTP_XOR_MULT_DOSStub_c3b1 {
  strings:
    $key_c3b1 = { 97 d9 [2] e3 c1 [2] a4 c3 [2] e3 d2 [2] ad de [2] a1 d4 [2] b6 df [2] ad 91 [2] 90 }

  condition:
    any of them
}