rule TTP_XOR_MULT_DOSStub_c6b7 {
  strings:
    $key_c6b7 = { 92 df [2] e6 c7 [2] a1 c5 [2] e6 d4 [2] a8 d8 [2] a4 d2 [2] b3 d9 [2] a8 97 [2] 95 }

  condition:
    any of them
}