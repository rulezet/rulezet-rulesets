rule TTP_XOR_MULT_DOSStub_0ab7 {
  strings:
    $key_0ab7 = { 5e df [2] 2a c7 [2] 6d c5 [2] 2a d4 [2] 64 d8 [2] 68 d2 [2] 7f d9 [2] 64 97 [2] 59 }

  condition:
    any of them
}