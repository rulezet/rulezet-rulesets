rule TTP_XOR_MULT_DOSStub_c4b7 {
  strings:
    $key_c4b7 = { 90 df [2] e4 c7 [2] a3 c5 [2] e4 d4 [2] aa d8 [2] a6 d2 [2] b1 d9 [2] aa 97 [2] 97 }

  condition:
    any of them
}