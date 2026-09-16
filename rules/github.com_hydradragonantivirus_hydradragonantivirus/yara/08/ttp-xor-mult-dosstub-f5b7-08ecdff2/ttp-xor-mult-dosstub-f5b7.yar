rule TTP_XOR_MULT_DOSStub_f5b7 {
  strings:
    $key_f5b7 = { a1 df [2] d5 c7 [2] 92 c5 [2] d5 d4 [2] 9b d8 [2] 97 d2 [2] 80 d9 [2] 9b 97 [2] a6 }

  condition:
    any of them
}