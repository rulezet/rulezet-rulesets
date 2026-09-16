rule TTP_XOR_MULT_DOSStub_f1b7 {
  strings:
    $key_f1b7 = { a5 df [2] d1 c7 [2] 96 c5 [2] d1 d4 [2] 9f d8 [2] 93 d2 [2] 84 d9 [2] 9f 97 [2] a2 }

  condition:
    any of them
}